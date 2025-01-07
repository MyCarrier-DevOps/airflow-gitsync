package main

import (
	"context"
	"fmt"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v67/github"
	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	githubauth "github.com/jferrl/go-githubauth"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"io"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func NewVault(roleID, secretID string, vault_addr string) (*vault.Client, error) {
	ctx := context.Background()
	vault_addr = strings.SplitAfter(vault_addr, "://")[1]
	client, err := vault.New(
		vault.WithAddress("https://"+strings.Trim(vault_addr, "'")),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Error(err)
	}
	resp, err := client.Auth.AppRoleLogin(
		ctx,
		schema.AppRoleLoginRequest{
			RoleId:   roleID,
			SecretId: secretID,
		},
	)
	if err != nil {
		log.Error(err)
	}

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		log.Error(err)
	}
	vc := client
	return vc, err
}

type GithubSession struct {
	roleID    string
	secretID  string
	auth      *oauth2.Token
	vault     *vault.Client
	pem       string
	appID     string
	installID string
	client    *github.Client
}

func NewGithubSession(roleID, secretID, organization string) (*GithubSession, error) {
	session := &GithubSession{
		roleID:   roleID,
		secretID: secretID,
	}
	err := session.renewVault()
	if err != nil {
		return nil, err
	}
	err = session.pullSecrets(organization)
	if err != nil {
		return nil, err
	}
	err = session.authenticate()
	if err != nil {
		return nil, err
	}
	session.connect()
	return session, nil
}

func (s *GithubSession) renewVault() error {
	vault_addr, ok := os.LookupEnv("VAULT_ADDR")
	if !ok {
		log.Error("VAULT_ADDR is not present")
	}
	vault, err := NewVault(s.roleID, s.secretID, vault_addr)
	if err != nil {
		return err
	}
	s.vault = vault
	return nil
}

func (s *GithubSession) pullSecrets(organization string) error {
	ctx := context.Background()
	secret, err := s.vault.Secrets.KvV2Read(ctx, "github/"+organization, vault.WithMountPath("DevOps"))
	if err != nil {
		return err
	}
	data := secret.Data.Data
	s.pem = data["PrivateKey"].(string)
	s.appID = data["AppId"].(string)
	s.installID = data["InstallationId"].(string)
	return nil
}

func (s *GithubSession) authenticate() error {
	privateKey := []byte(s.pem)
	appID, _ := strconv.ParseInt(s.appID, 10, 64)
	installationID, _ := strconv.ParseInt(s.installID, 10, 64)
	appTokenSource, err := githubauth.NewApplicationTokenSource(appID, privateKey)
	if err != nil {
		fmt.Println("Error creating application token source:", err)
		return err
	}
	installationTokenSource := githubauth.NewInstallationTokenSource(installationID, appTokenSource)
	httpClient := oauth2.NewClient(context.Background(), installationTokenSource)
	token, err := installationTokenSource.Token()
	if err != nil {
		fmt.Println("Error generating token:", err)
		return err
	}
	s.client = github.NewClient(httpClient)
	s.auth = token
	return nil
}

func (s *GithubSession) connect() {
	// Connection is established in authenticate method
}

func repoCleanup(path string, repos []string) {
	directories, err := os.ReadDir(path)
	if err != nil {
		log.Error(err)
	}
	for _, d := range directories {
		if !contains(repos, d.Name()) {
			fmt.Printf("%s Cleaning up %s from %s\n", time.Now().Format(time.RFC3339), d.Name(), path)
			os.RemoveAll(filepath.Join(path, d.Name()))
		}
	}
}

func clone(path string, repos []map[string]string) {
	var wg sync.WaitGroup
	for _, repo := range repos {
		wg.Add(1)
		go func(repo map[string]string) {
			defer wg.Done()
			repoPath := filepath.Join(path, "git_"+repo["repository"])
			if _, err := os.Stat(repoPath); os.IsNotExist(err) {
				fmt.Printf("%s Cloning %s from %s into %s\n", time.Now().Format(time.RFC3339), repo["repository"], repo["org"], path)
				cloneRepo(repoPath, repo["token"], repo["org"], repo["repository"])
			} else {
				fmt.Printf("%s Pulling %s from %s into %s\n", time.Now().Format(time.RFC3339), repo["repository"], repo["org"], path)
				pullRepo(repoPath, repo["token"], repo["org"], repo["repository"])
			}
		}(repo)
	}
	wg.Wait()
}

func cloneRepo(path, token, org, repo string) {
	_, err := git.PlainClone(path, false, &git.CloneOptions{
		Auth: &http.BasicAuth{
			Username: "oauth2", // yes, this can be anything except an empty string
			Password: token,
		},
		URL:      fmt.Sprintf("https://github.com/%s/%s.git", org, repo),
		Progress: io.Discard,
	})
	if err != nil {
		fmt.Println("Error:", err)
	}
}

func pullRepo(path, token, org, repo string) {
	r, err := git.PlainOpen(path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	w, err := r.Worktree()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	err = w.Pull(&git.PullOptions{
		Auth: &http.BasicAuth{
			Username: "oauth2", // yes, this can be anything except an empty string
			Password: token,
		},
	})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		fmt.Println("Error:", err)
		fmt.Println("Unable to pull, removing directory and cloning a fresh copy.")
		os.RemoveAll(path)
		cloneRepo(path, token, org, repo)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file, proceeding with environment variables")
	}
	roleID, ok := os.LookupEnv("ROLE_ID")
	if !ok {
		log.Error("ROLE_ID is not present")
	}
	secretID, ok := os.LookupEnv("SECRET_ID")
	if !ok {
		log.Error("SECRET_ID is not present")
	}
	dagPath, ok := os.LookupEnv("DAG_PATH")
	if !ok {
		log.Error("DAG_PATH is not present")
	}
	orgNames := []string{"MyCarrier-DevOps", "MyCarrier-Engineering"}

	if _, err := os.Stat(dagPath); os.IsNotExist(err) {
		os.MkdirAll(dagPath, os.ModePerm)
	}

	operation := os.Args[1]
	loop := true
	for loop {
		var repos []map[string]string
		for _, orgName := range orgNames {
			githubSession, err := NewGithubSession(roleID, secretID, orgName)
			if err != nil {
				log.Error(err)
			}
			err = withExponentialBackoff(context.Background(), func() error {
				reposObj, _, err := githubSession.client.Search.Repositories(context.Background(), fmt.Sprintf("org:%s topic:airflow-dags template:false", orgName), nil)
				if err != nil {
					return err
				}
				for _, repo := range reposObj.Repositories {
					repos = append(repos, map[string]string{
						"repository": repo.GetName(),
						"token":      githubSession.auth.AccessToken,
						"org":        orgName,
					})
				}
				return nil
			})
			if err != nil {
				log.Error(err)
			}
			clone(dagPath, repos)
		}
		repoCleanup(dagPath, getRepoNames(repos))
		if operation == "pull" {
			loop = false
		} else {
			time.Sleep(300 * time.Second)
		}
	}
}

func getRepoNames(repos []map[string]string) []string {
	var names []string
	for _, repo := range repos {
		names = append(names, "git_"+repo["repository"])
	}
	return names
}

func withExponentialBackoff(ctx context.Context, fn func() error) error {
	var baseDelay time.Duration = 1 * time.Second
	var maxDelay time.Duration = 32 * time.Second
	var maxRetries int = 10

	for i := 0; i < maxRetries; i++ {
		err := fn()
		if err == nil {
			return nil
		}

		delay := baseDelay * time.Duration(math.Pow(2, float64(i)))
		if delay > maxDelay {
			delay = maxDelay
		}

		jitter := time.Duration(rand.Int63n(int64(delay / 2)))
		delay = delay + jitter

		log.Printf("Request failed: %v. Retrying in %v...", err, delay)
		time.Sleep(delay)
	}

	return fmt.Errorf("max retries reached")
}

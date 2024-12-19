package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v67/github"
	vault "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	githubauth "github.com/jferrl/go-githubauth"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

//type Vault struct {
//  Client *vault.Client
//}

func NewVault(roleID, secretID string, vault_addr string) (*vault.Client, error) {
	ctx := context.Background()
	client, err := vault.New(
		vault.WithAddress("https://"+strings.Trim(vault_addr, "'")),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Auth.AppRoleLogin(
		ctx,
		schema.AppRoleLoginRequest{
			RoleId:   roleID,
			SecretId: secretID,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		log.Fatal(err)
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
	vault, err := NewVault(s.roleID, s.secretID, os.Getenv("VAULT_ADDR"))
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
		log.Fatal(err)
	}
	for _, d := range directories {
		if !contains(repos, d.Name()) {
			fmt.Printf("%s Cleaning up %s from %s\n", time.Now().Format(time.RFC3339), d.Name(), path)
			os.RemoveAll(filepath.Join(path, d.Name()))
		}
	}
}

func clone(path string, repos []map[string]string) {
	for _, repo := range repos {
		repoPath := filepath.Join(path, "git_"+repo["repository"])
		if _, err := os.Stat(repoPath); os.IsNotExist(err) {
			fmt.Printf("%s Cloning %s from %s into %s\n", time.Now().Format(time.RFC3339), repo["repository"], repo["org"], path)
			cloneRepo(repoPath, repo["token"], repo["org"], repo["repository"])
		} else {
			fmt.Printf("%s Pulling %s from %s into %s\n", time.Now().Format(time.RFC3339), repo["repository"], repo["org"], path)
			pullRepo(repoPath, repo["token"], repo["org"], repo["repository"])
		}
	}
}

func cloneRepo(path, token, org, repo string) {
	cmd := exec.Command("git", "clone", fmt.Sprintf("https://oauth2:%s@github.com/%s/%s.git", token, org, repo), path)
	err := cmd.Run()
	if err != nil {
		fmt.Println("Error:", err)
	}
}

func pullRepo(path, token, org, repo string) {
	cmd := exec.Command("git", "-C", path, "pull")
	err := cmd.Run()
	if err != nil {
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
		print("Error loading .env file, proceeding with environment variables")
	}
	roleID := os.Getenv("ROLE_ID")
	secretID := os.Getenv("SECRET_ID")
	dagPath := os.Getenv("DAG_PATH")
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
				log.Fatal(err)
			}
			reposObj, _, err := githubSession.client.Search.Repositories(context.Background(), fmt.Sprintf("org:%s topic:airflow-dags template:false", orgName), nil)
			if err != nil {
				log.Fatal(err)
			}
			for _, repo := range reposObj.Repositories {
				repos = append(repos, map[string]string{
					"repository": repo.GetName(),
					"token":      githubSession.auth.AccessToken,
					"org":        orgName,
				})
			}
			clone(dagPath, repos)
		}
		repoCleanup(dagPath, getRepoNames(repos))
		if operation == "pull" {
			loop = false
		} else {
			time.Sleep(30 * time.Second)
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

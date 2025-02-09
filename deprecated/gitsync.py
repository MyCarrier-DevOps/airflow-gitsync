#!/usr/bin/env python3
import shutil
import os
from pathlib import Path
import hvac
import sys
import time
import datetime
from github import Auth, Github
from git import Repo, GitCommandError
from dotenv import load_dotenv
import gc

OPERATION = sys.argv[1]

if OPERATION is None or OPERATION == 'help':
    print("Please provide a valid operation.")
    print("Valid operations")
    print("'help' for help.")
    print("'sync' for recurring sync.")
    print("'pull' for a one time pull.")


class Vault:
    def __init__(self, role_id, secret_id):
        self.Client = hvac.Client()
        try:
            self.Client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id,
            )
        except Exception as error:
            raise error


class GithubSession:
    def __init__(self, role_id, secret_id, organization):
        self.role_id = role_id
        self.secret_id = secret_id
        self.auth = None
        self.vault = None
        self.pem = None
        self.appid = None
        self.installid = None
        self.session = None
        self.renew_vault()
        self.pull_secrets(organization)
        self.authenticate()
        self.connect()

    def renew_vault(self):
        self.vault = Vault(role_id=self.role_id, secret_id=self.secret_id)

    def pull_secrets(self, organization: str):
        v = self.vault.Client.secrets.kv.v2
        self.pem = v.read_secret_version(mount_point='DevOps', path=f'github/{organization}',
                                                    raise_on_deleted_version=False)['data']['data']['PrivateKey']
        self.appid = v.read_secret_version(mount_point='DevOps', path=f'github/{organization}',
                                                    raise_on_deleted_version=False)['data']['data']['AppId']
        self.installid = int(v.read_secret_version(mount_point='DevOps', path=f'github/{organization}',
                                                    raise_on_deleted_version=False)['data']['data']['InstallationId'])

    def authenticate(self):
        self.auth = Auth.AppAuth(self.appid, self.pem).get_installation_auth(self.installid)

    def connect(self):
        self.session = Github(auth=self.auth)


def repo_cleanup(path: str, repos: list[str]):
    directories = [d for d in os.listdir(path)]
    for d in directories:
        if d not in repos:
            print(f'{datetime.datetime.now()} Cleaning up {d} from {path}')
            shutil.rmtree(path+'/'+d)


def clone(path: str, repos: list[object]):
    for repo in repos:
        Path(path).mkdir(parents=True, exist_ok=True)
        thisPath = Path(f'{path}/git_{repo["repository"]}')
        auth = Auth.Token(repo["token"])
        try:
            if thisPath.is_dir():
                print(f'{datetime.datetime.now()} Pulling {repo["repository"]} from {repo["org"]} into {path}')
                thisRepo = Repo(thisPath.__str__())
                origin = thisRepo.remotes.origin
                origin.set_url(f'https://oauth2:{repo["token"]}@github.com/{repo["org"]}/{repo["repository"]}.git')
                try:
                    origin.pull()
                except:
                    print("Unable to pull, removing directory and cloning a fresh copy.")
                    shutil.rmtree(thisPath)
                    print(f'{datetime.datetime.now()} Cloning {repo["repository"]} from {repo["org"]} into {path}')
                    clonePath = f'https://oauth2:{repo["token"]}@github.com/{repo["org"]}/{repo["repository"]}.git'
                    thisRepo = Repo.clone_from(clonePath, thisPath)
                    thisRepo.__del__()
                finally: 
                    thisRepo.__del__()

            else:
                print(f'{datetime.datetime.now()} Cloning {repo["repository"]} from {repo["org"]} into {path}')
                clonePath = f'https://oauth2:{repo["token"]}@github.com/{repo["org"]}/{repo["repository"]}.git'
                thisRepo = Repo.clone_from(clonePath, thisPath)
                thisRepo.__del__()
        except Exception as e:
            raise e
            



if __name__ == '__main__':
    # Setup vars
    ROLE_ID = os.getenv('ROLE_ID')
    if ROLE_ID == None:
        load_dotenv()
        ROLE_ID = os.getenv('ROLE_ID')

    SECRET_ID = os.getenv('SECRET_ID')
    if SECRET_ID == None:
        load_dotenv()
        SECRET_ID = os.getenv('SECRET_ID')

    VAULT_ADDR = os.getenv('VAULT_ADDR')
    if VAULT_ADDR == None:
        load_dotenv()
        VAULT_ADDR = os.getenv('VAULT_ADDR')

    DAG_PATH = os.getenv('DAG_PATH')
    if DAG_PATH == None:
        load_dotenv()
        DAG_PATH = os.getenv('DAG_PATH')
    ORG_NAMES = ['MyCarrier-DevOps', 'MyCarrier-Engineering']

    if not os.path.isdir(DAG_PATH):
        os.makedirs(DAG_PATH)
    loop = True
    while loop:
        repos = []
        for ORG_NAME in ORG_NAMES:
            github = GithubSession(ROLE_ID, SECRET_ID, ORG_NAME)
            org = github.session.get_organization(ORG_NAME)
            reposObj = github.session.search_repositories(query=f'org:{ORG_NAME} topic:airflow-dags template:false')
            theseRepos = [{"repository": repo.name, "token": github.auth.token, "org": ORG_NAME} for repo in reposObj]
            repos.extend(theseRepos)
            try:
                clone(DAG_PATH, theseRepos)
            except Exception as e:
                print(e)
                github = GithubSession(ROLE_ID, SECRET_ID, ORG_NAME)
                clone(DAG_PATH, theseRepos)
        repo_cleanup(DAG_PATH, [f"git_{repo['repository']}" for repo in repos])
        if OPERATION == 'pull':
                loop = False
        else:
            time.sleep(30)
        repos = []
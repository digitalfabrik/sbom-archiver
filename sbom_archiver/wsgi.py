#!/usr/bin/env python
# -*- coding: utf-8 -*-

import configparser

import requests
from flask import Flask, request, jsonify

from git import Repo

app = Flask(__name__)

CONFIG = configparser.ConfigParser()
CONFIG.read('/etc/sbom-archiver.ini')
GITHUB_TOKEN = CONFIG["github"]["token"]

SBOM_ARCHIVE_REPO_URL = CONFIG["archive"]["repo-url"]
SBOM_ARCHIVE_REPO_LOCAL_PATH = CONFIG["archive"]["path"]

try:
    sbom_repo = Repo(SBOM_ARCHIVE_REPO_LOCAL_PATH)
except:
    sbom_repo = Repo.clone_from(SBOM_ARCHIVE_REPO_URL, SBOM_ARCHIVE_REPO_LOCAL_PATH)

@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json

    if 'repo_name' not in data or 'commit_hash' not in data:
        return jsonify({'error': 'Missing required arguments'}), 400

    repo_name = data['repo_name']
    commit_hash = data['commit_hash']

    owner, repo = repo_name.split('/')

    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/vnd.github.hawkgirl-preview+json'
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return jsonify({'error': 'Failed to fetch SBOM'}), 500
    sbom_data = response.json()

    repo_path = f"{SBOM_ARCHIVE_REPO_LOCAL_PATH}/{repo_name}"
    if not os.path.exists(repo_path):
        os.makedirs(repo_path)

    filename = f"{repo_name}/{commit_hash}.json"
    filepath = f"{SBOM_ARCHIVE_REPO_LOCAL_PATH}/{filename}"

    with open(filepath, 'w') as f:
        f.write(str(sbom_data))

    sbom_repo.index.add([filepath])
    sbom_repo.index.commit(f"Add {repo_name} SBOM for {commit_hash}")
    origin = sbom_repo.remotes.origin
    origin.push()

    return jsonify({'message': 'SBOM stored successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)

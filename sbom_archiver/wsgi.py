#!/usr/bin/env python
# -*- coding: utf-8 -*-

import configparser
import json
import os

from hashlib import sha256
from hmac import HMAC, compare_digest

import requests
from flask import Flask, request, jsonify

from git import Repo

application = Flask(__name__)

CONFIG = configparser.ConfigParser()
CONFIG.read('/etc/sbom-archiver.ini')
GITHUB_TOKEN = CONFIG["github"]["token"]

SBOM_ARCHIVE_REPO_URL = CONFIG["archive"]["repo-url"]
SBOM_ARCHIVE_REPO_LOCAL_PATH = CONFIG["archive"]["path"]
VALID_TOKENS = CONFIG["tokens"]

try:
    sbom_repo = Repo(SBOM_ARCHIVE_REPO_LOCAL_PATH)
except:
    sbom_repo = Repo.clone_from(SBOM_ARCHIVE_REPO_URL, SBOM_ARCHIVE_REPO_LOCAL_PATH)

def verify_signature(req, token):
     received_sign = req.headers.get('X-Hub-Signature-256').split('sha256=')[-1].strip()
     secret = token.encode()
     expected_sign = HMAC(key=secret, msg=req.data, digestmod=sha256).hexdigest()
     return compare_digest(received_sign, expected_sign)

@application.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    if 'ref' not in data or 'repository' not in data:
        return jsonify({'error': 'Missing required arguments'}), 400

    repo = data['repository']['name']
    owner = data['repository']['owner']['name']
    commit_hash = data['after']
    org_repo_name = f"{owner}/{repo}"

    if not verify_signature(request, VALID_TOKENS[org_repo_name]):
        return jsonify({'error': 'Invalid or missing token'}), 401

    if not data["ref"] in f"refs/heads/{CONFIG['default-branch'][org_repo_name]}":
        return jsonify({'message': 'Push event not on default branch, not archiving SBOM.'}), 200

    url = f"https://api.github.com/repos/{org_repo_name}/dependency-graph/sbom"
    headers = {
        'Authorization': f'token {GITHUB_TOKEN}',
        'Accept': 'application/json'
    }
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return jsonify({'error': 'Failed to fetch SBOM'}), 500
    sbom_data = response.json()

    repo_path = f"{SBOM_ARCHIVE_REPO_LOCAL_PATH}/{org_repo_name}"
    if not os.path.exists(repo_path):
        os.makedirs(repo_path)
    filename = f"{org_repo_name}/{commit_hash}.json"
    filepath = f"{SBOM_ARCHIVE_REPO_LOCAL_PATH}/{filename}"

    with open(filepath, 'w') as f:
        f.write(json.dumps(sbom_data, indent=2))

    sbom_repo.index.add([filepath])
    sbom_repo.index.commit(f"Add {org_repo_name} SBOM for {commit_hash}")
    origin = sbom_repo.remotes.origin
    origin.push()

    return jsonify({'message': 'SBOM stored successfully'}), 200

if __name__ == '__main__':
    application.run()



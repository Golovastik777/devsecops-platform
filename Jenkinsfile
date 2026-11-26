// Jenkins version of the pipeline. Stages call the same ci/*.sh scripts as GitHub Actions
// and GitLab CI. Agent: label "docker" with Docker, kind, kubectl, helm and python3.
// Credentials: defectdojo-url, defectdojo-api-key, anthropic-api-key (Secret text).

pipeline {
  agent { label 'docker' }

  options {
    timestamps()
    timeout(time: 60, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '30'))
    disableConcurrentBuilds(abortPrevious: true)
  }

  environment {
    REPORTS_DIR = 'reports'
    IMAGE = 'ghcr.io/golovastik777/kb-assistant:ci'
  }

  stages {
    stage('Unit tests') {
      steps {
        sh '''
          python3 -m venv .venv
          .venv/bin/pip install -q --require-hashes -r app/requirements.txt -r app/requirements-dev.txt -r ci/requirements.txt
          mkdir -p reports
          (cd app && ../.venv/bin/python -m pytest --junitxml=../reports/junit-app.xml)
          .venv/bin/python -m pytest -q ci/tests triage/tests --junitxml=reports/junit-ci.xml
        '''
      }
      post { always { junit 'reports/junit-*.xml' } }
    }

    stage('Static scans') {
      parallel {
        stage('Secrets') { steps { sh 'bash ci/scan-secrets.sh' } }
        stage('SAST')    { steps { sh 'bash ci/scan-sast.sh' } }
        stage('SCA')     { steps { sh 'bash ci/scan-deps.sh' } }
        stage('IaC')     { steps { sh 'bash ci/scan-iac.sh' } }
        stage('Pulumi tests') {
          steps {
            sh '''
              python3 -m venv .venv-pulumi
              .venv-pulumi/bin/pip install -q --require-hashes -r infra/pulumi/requirements.txt
              (cd infra/pulumi && ../../.venv-pulumi/bin/python -m pytest)
            '''
          }
        }
        stage('Policy tests') {
          steps {
            sh '''
              python3 -m venv .venv-ansible
              .venv-ansible/bin/pip install -q --require-hashes -r infra/ansible/requirements.txt
              export PATH="$PWD/.venv-ansible/bin:$PATH"
              (cd infra/ansible && ansible-galaxy collection install -r requirements.yml && ansible-lint --offline hardening.yml roles/)
              bash ci/test-policies.sh
            '''
          }
        }
      }
    }

    stage('Build + image scan') {
      steps { sh 'bash ci/build-image.sh' }
    }

    stage('Dynamic tests') {
      parallel {
        stage('DAST') {
          steps { sh 'bash ci/run-app.sh && bash ci/dast.sh' }
          post { always { sh 'docker rm -f kb-assistant-dast || true' } }
        }
        stage('Kubernetes e2e') {
          environment { KIND_CLUSTER = "devsecops-${env.BUILD_NUMBER}" }
          steps { sh 'bash ci/e2e-kind.sh' }
          post { always { sh 'kind delete cluster --name "$KIND_CLUSTER" || true' } }
        }
      }
    }

    stage('Security gate') {
      steps {
        sh '.venv/bin/python ci/security_gate.py'
      }
    }
  }

  post {
    always {
      // Reporting runs even when the gate fails, so the findings reach DefectDojo.
      withCredentials([
        string(credentialsId: 'defectdojo-url', variable: 'DD_URL'),
        string(credentialsId: 'defectdojo-api-key', variable: 'DD_API_KEY'),
        string(credentialsId: 'anthropic-api-key', variable: 'ANTHROPIC_API_KEY'),
      ]) {
        sh '''
          .venv/bin/python ci/security_gate.py --no-fail >/dev/null
          .venv/bin/python ci/upload_defectdojo.py || true
          .venv/bin/python triage/ai_triage.py || true
        '''
      }
      recordIssues(tools: [sarif(pattern: 'reports/security.sarif')])
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
    }
  }
}

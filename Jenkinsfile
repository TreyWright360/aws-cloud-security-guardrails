pipeline {
    agent { label 'terraform-aws' }

    environment {
        TF_ROOT                   = 'terraform'
        TF_PLAN                   = 'tfplan'
        TF_IN_AUTOMATION          = 'true'
        TF_INPUT                  = 'false'
        AWS_DEFAULT_REGION        = 'us-east-1'
        AWS_EC2_METADATA_DISABLED = 'true'
    }

    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 90, unit: 'MINUTES')
    }

    stages {
        stage('Checkout') {
            steps {
                deleteDir()
                checkout scm
                sh '''
                    set -eu
                    echo "Commit: $(git rev-parse HEAD)"
                    test -z "$(git status --short)"
                '''
            }
        }

        stage('Verify Toolchain') {
            steps {
                sh '''
                    set -eu
                    for tool in terraform python3 trivy aws jq shasum; do
                        command -v "$tool" >/dev/null 2>&1 || {
                            echo "ERROR: missing required tool: $tool" >&2
                            exit 1
                        }
                    done
                    terraform version
                    python3 --version
                    trivy --version
                    aws --version
                '''
            }
        }

        stage('Validate and Test') {
            parallel {
                stage('Terraform') {
                    steps {
                        sh '''
                            set -eu
                            terraform fmt -check -recursive -diff
                            terraform -chdir="$TF_ROOT" init \
                                -backend=false -input=false -no-color \
                                -lockfile=readonly
                            terraform -chdir="$TF_ROOT" validate -no-color
                            terraform -chdir="$TF_ROOT" test -no-color
                        '''
                    }
                }

                stage('Python') {
                    steps {
                        sh '''
                            set -eu
                            python3 -m compileall -q src tests
                            python3 -m unittest discover -s tests -p 'test_*.py' -v
                            python3 tests/simulate_drift.py --mode dry-run
                        '''
                    }
                }
            }
        }

        stage('IaC Security Gate') {
            steps {
                sh '''
                    set -eu
                    trivy config --quiet --severity HIGH,CRITICAL \
                        --exit-code 1 "$TF_ROOT"
                    scripts/test_security_gate.sh
                '''
            }
        }

        stage('Initialize Production Backend') {
            when {
                beforeAgent true
                allOf {
                    branch 'main'
                    not { changeRequest() }
                }
            }
            steps {
                withCredentials([
                    [$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-devsecops-creds'],
                    string(credentialsId: 'aws-prod-account-id', variable: 'AWS_PROD_ACCOUNT_ID'),
                    file(credentialsId: 'terraform-backend-config', variable: 'TF_BACKEND_CONFIG')
                ]) {
                    sh '''
                        set -eu
                        caller_account="$(aws sts get-caller-identity --query Account --output text)"
                        test "$caller_account" = "$AWS_PROD_ACCOUNT_ID"
                        terraform -chdir="$TF_ROOT" init -reconfigure \
                            -input=false -no-color -lockfile=readonly \
                            -backend-config="$TF_BACKEND_CONFIG"
                    '''
                }
            }
        }

        stage('Production Plan') {
            when {
                beforeAgent true
                allOf {
                    branch 'main'
                    not { changeRequest() }
                }
            }
            steps {
                withCredentials([
                    [$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-devsecops-creds'],
                    string(credentialsId: 'aws-prod-account-id', variable: 'AWS_PROD_ACCOUNT_ID')
                ]) {
                    sh '''
                        set -eu
                        test "$(aws sts get-caller-identity --query Account --output text)" = "$AWS_PROD_ACCOUNT_ID"
                        rc=0
                        terraform -chdir="$TF_ROOT" plan -input=false -no-color \
                            -lock-timeout=5m -detailed-exitcode -out="$TF_PLAN" || rc=$?
                        test "$rc" -ne 1
                        terraform -chdir="$TF_ROOT" show -no-color "$TF_PLAN" > "$TF_ROOT/tfplan.txt"
                        terraform -chdir="$TF_ROOT" show -json "$TF_PLAN" > "$TF_ROOT/tfplan.json"
                        jq '{
                          create: ([.resource_changes[]? | select(.change.actions == ["create"])] | length),
                          update: ([.resource_changes[]? | select(.change.actions == ["update"])] | length),
                          delete: ([.resource_changes[]? | select(.change.actions == ["delete"])] | length),
                          replace: ([.resource_changes[]? | select((.change.actions | index("delete")) and (.change.actions | index("create")))] | length)
                        }' "$TF_ROOT/tfplan.json" > "$TF_ROOT/plan-summary.json"
                        (cd "$TF_ROOT" && shasum -a 256 "$TF_PLAN" | awk '{print $1}' > tfplan.sha256)
                        cat "$TF_ROOT/plan-summary.json"
                        cat "$TF_ROOT/tfplan.txt"
                    '''
                }
                archiveArtifacts artifacts: 'terraform/plan-summary.json,terraform/tfplan.sha256', fingerprint: true
                stash name: 'approved-terraform-plan', includes: 'terraform/tfplan,terraform/tfplan.sha256,terraform/lambda_payload.zip'
            }
        }

        stage('Production Approval') {
            when {
                beforeInput true
                allOf {
                    branch 'main'
                    not { changeRequest() }
                }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            input {
                message 'Review the Terraform plan output and plan summary. Apply this exact saved plan?'
                ok 'Apply saved plan'
                submitter 'cloud-platform-approvers'
                submitterParameter 'APPROVED_BY'
            }
            steps {
                echo "Deployment approved by ${APPROVED_BY}"
            }
        }

        stage('Apply Saved Plan') {
            when {
                beforeAgent true
                allOf {
                    branch 'main'
                    not { changeRequest() }
                }
            }
            steps {
                unstash 'approved-terraform-plan'
                withCredentials([
                    [$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-devsecops-creds'],
                    string(credentialsId: 'aws-prod-account-id', variable: 'AWS_PROD_ACCOUNT_ID'),
                    file(credentialsId: 'terraform-backend-config', variable: 'TF_BACKEND_CONFIG')
                ]) {
                    sh '''
                        set -eu
                        test "$(aws sts get-caller-identity --query Account --output text)" = "$AWS_PROD_ACCOUNT_ID"
                        actual_hash="$(cd "$TF_ROOT" && shasum -a 256 "$TF_PLAN" | awk '{print $1}')"
                        test "$actual_hash" = "$(cat "$TF_ROOT/tfplan.sha256")"
                        terraform -chdir="$TF_ROOT" init -reconfigure \
                            -input=false -no-color -lockfile=readonly \
                            -backend-config="$TF_BACKEND_CONFIG"
                        terraform -chdir="$TF_ROOT" apply -input=false -no-color \
                            -lock-timeout=5m "$TF_PLAN"
                    '''
                }
            }
        }

        stage('Post-Deploy Verification') {
            when {
                beforeAgent true
                allOf {
                    branch 'main'
                    not { changeRequest() }
                }
            }
            steps {
                withCredentials([
                    [$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-devsecops-creds'],
                    file(credentialsId: 'terraform-backend-config', variable: 'TF_BACKEND_CONFIG')
                ]) {
                    sh '''
                        set -eu
                        terraform -chdir="$TF_ROOT" init -reconfigure \
                            -input=false -no-color -lockfile=readonly \
                            -backend-config="$TF_BACKEND_CONFIG"
                        scripts/verify_deployment.sh
                    '''
                }
                archiveArtifacts artifacts: 'verify/*.json', fingerprint: true
            }
        }
    }

    post {
        always {
            sh '''
                rm -f terraform/tfplan terraform/tfplan.* \
                    terraform/post-apply.tfplan terraform/lambda_payload.zip
            '''
            deleteDir()
        }
        success { echo 'Validation and all applicable deployment stages passed.' }
        failure { echo 'Pipeline failed; production apply was not completed successfully.' }
    }
}

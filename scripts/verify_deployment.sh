#!/usr/bin/env sh
set -eu

TF_ROOT="${TF_ROOT:-terraform}"
mkdir -p verify

rc=0
terraform -chdir="$TF_ROOT" plan -input=false -no-color \
  -lock-timeout=5m -detailed-exitcode -out=post-apply.tfplan || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "ERROR: post-apply Terraform plan was not empty (exit code $rc)" >&2
  exit 1
fi

function_arn="$(terraform -chdir="$TF_ROOT" output -raw lambda_function_arn)"
rule_name="$(terraform -chdir="$TF_ROOT" output -raw eventbridge_rule_name)"

aws lambda invoke \
  --function-name "$function_arn" \
  --cli-binary-format raw-in-base64-out \
  --payload '{"source":"jenkins.post-deploy","detail":{"eventName":"PipelineSmokeTest"}}' \
  verify/lambda-response.json > verify/lambda-invoke.json

jq -e '.StatusCode == 200 and (has("FunctionError") | not)' \
  verify/lambda-invoke.json >/dev/null
jq -e '.statusCode == 200' verify/lambda-response.json >/dev/null

aws events list-targets-by-rule --rule "$rule_name" > verify/eventbridge-targets.json
jq -e --arg arn "$function_arn" '[.Targets[]?.Arn] | index($arn) != null' \
  verify/eventbridge-targets.json >/dev/null

echo "Post-deploy convergence, Lambda invocation, and EventBridge target checks passed."

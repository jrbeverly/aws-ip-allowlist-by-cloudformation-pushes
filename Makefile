VENV := .venv
REGION := us-west-2
STACK := ipallow
BUCKET := ipallow-220087710539-us-west-2
ROLE_ARN := arn:aws:iam::220087710539:role/ipallow-cfn-admin
CODE_KEY := ip-allowlist-sync/$(shell cat runtime/src/*.py runtime/requirements.txt | sha256sum | cut -c1-12)/function.zip

.PHONY: setup test package clean bootstrap deploy sync destroy

$(VENV):
	python3 -m venv $(VENV)

setup: $(VENV)
	$(VENV)/bin/pip install -r tests/runtime/requirements.txt

test: $(VENV)
	$(VENV)/bin/python -m pytest tests/runtime/

package:
	rm -rf runtime/build runtime/function.zip
	pip install -q -r runtime/requirements.txt -t runtime/build/
	cp runtime/src/*.py runtime/build/
	cd runtime/build && zip -qr ../function.zip . -x '*.dist-info/*' -x '*__pycache__*'

bootstrap:
	aws cloudformation deploy --region $(REGION) --stack-name $(STACK)-bootstrap \
	  --template-file bootstrap.yaml --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset

deploy: package bootstrap
	aws s3 cp --region $(REGION) examples/feeds/sample-ipv4.txt s3://$(BUCKET)/feeds/ipv4.txt
	aws s3 cp --region $(REGION) runtime/function.zip s3://$(BUCKET)/$(CODE_KEY)
	aws cloudformation deploy --region $(REGION) --stack-name $(STACK) \
	  --template-file templates/waf-ip-set-sync/regional.yaml \
	  --capabilities CAPABILITY_NAMED_IAM --role-arn $(ROLE_ARN) --no-fail-on-empty-changeset \
	  --parameter-overrides pFeedName=$(STACK) pSourceType=S3 \
	    pSourceLocation=s3://$(BUCKET)/feeds/ipv4.txt pSourceS3Bucket=$(BUCKET) \
	    pLambdaCodeS3Bucket=$(BUCKET) pLambdaCodeS3Key=$(CODE_KEY)
	$(MAKE) sync

sync:
	aws lambda invoke --region $(REGION) --function-name $(STACK)-sync \
	  --log-type Tail --query LogResult --output text /dev/null | base64 -d
	aws cloudformation wait stack-update-complete --region $(REGION) --stack-name $(STACK)
	aws wafv2 get-ip-set --region $(REGION) --scope REGIONAL --name $(STACK)-ipv4 \
	  --id $$(aws ssm get-parameter --region $(REGION) --name /ip-allowlist/IPSets/$(STACK)/ipv4/id --query Parameter.Value --output text) \
	  --query IPSet.Addresses --output text

destroy:
	aws cloudformation delete-stack --region $(REGION) --stack-name $(STACK) --role-arn $(ROLE_ARN)
	aws cloudformation wait stack-delete-complete --region $(REGION) --stack-name $(STACK)

clean:
	rm -rf runtime/build runtime/function.zip $(VENV)

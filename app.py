from flask import Flask, jsonify, request, send_from_directory
import boto3
import json
import logging
import re

app = Flask(__name__, static_url_path='')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REGION = "us-east-2"  # You can also use "us-east-1" or "us-west-2" based on your preference
MODEL_ID = "us.anthropic.claude-3-5-sonnet-20241022-v2:0"  # Updated to use the Inference Profile ID

def get_claude_response(prompt):
    bedrock_runtime = boto3.client('bedrock-runtime', region_name=REGION)

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2000,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    })

    try:
        response = bedrock_runtime.invoke_model(
            modelId=MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=body
        )

        response_body = json.loads(response['body'].read())
        return response_body['content'][0]['text']
    except Exception as e:
        logger.error(f"Error invoking model: {str(e)}")
        raise

@app.route('/')
def home():
    return send_from_directory('static', 'index.html')

def generate_rules_from_openapi(openapi_spec, additional_context):
    prompt = f"""
    You are a security engineer that works at AWS. Your job is to create me a WAF ACL rules in JSON based upon a OpenAPI configuration and best practices. The most important rules that should be added as a baseline for all generated rules are the baseline rule groups, IP reputation rule group and the Rate based rule group. Do not add rules other than what are listed as part of the baseline, IP reputation, and rate-based group. The output should also be based on any compliance standards or tech stacks that are relevant to the API. All rules should follow a standard naming scheme. For each group, select the top most 3 rules that are important to the given OpenAPI context. Each rule should follow the following format:

    {{
        "Name": "CompanyName-RuleName",
        "Priority": integer,
        "OverrideAction": {{
        "None": {{}}
        }},
        "Statement": {{
        "ManagedRuleGroupStatement": {{
        "VendorName": "AWS",
        "Name": string (example: name_of_AWS_managed_rule_set),
        "ExcludedRules": []
        }}
        }},
        "VisibilityConfig": {{
        "SampledRequestsEnabled": boolean,
        "CloudWatchMetricsEnabled": boolean,
        "MetricName": "CompanyName-RuleName"
        }},
        "UrgencyCategory": string (one of: "Critical", "Recommended", "Additional")
    }}

    Categorize each rule based on its urgency:
    - Critical: Rules that are essential for immediate security and should be implemented without delay.
    - Recommended: Important rules that significantly enhance security but may have some flexibility in implementation timing.
    - Additional: Rules that provide extra layers of security but are not urgent.

    Here's the OpenAPI specification to analyze:

    {openapi_spec}

    Additional context about the API:

    {additional_context}

    Based on the OpenAPI specification and the additional context provided, generate the WAF ACL rules in JSON format. Include only the JSON output, without any additional explanation. Ensure each rule has an "UrgencyCategory" field.
    """
    response = get_claude_response(prompt)

    # Try to extract JSON from the response
    json_match = re.search(r'\{[\s\S]*\}', response)
    if json_match:
        try:
            waf_rules = json.loads(json_match.group(0))
            return json.dumps(waf_rules, indent=2)  # Return formatted JSON string
        except json.JSONDecodeError:
            return {"error": "Failed to parse JSON from the response", "raw_response": response}
    else:
        return {"error": "No JSON found in the response", "raw_response": response}

@app.route('/api/list-api-gateways', methods=['GET'])
def list_api_gateways():
    try:
        client = boto3.client('apigateway', region_name=REGION)
        response = client.get_rest_apis()
        apis = [{"name": item['name'], "arn": f"arn:aws:execute-api:{REGION}:{boto3.client('sts').get_caller_identity().get('Account')}:{item['id']}"} for item in response['items']]
        return jsonify({"apis": apis})
    except Exception as e:
        logger.error(f"Error listing API Gateways: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/generate-rules', methods=['POST'])
def generate_rules():
    data = request.json
    input_type = data.get('input_type')
    api_context = data.get('context', '')

    if input_type in ['arn', 'list']:
        api_arn = data.get('api_arn')
        if not api_arn:
            return jsonify({"error": "API Gateway ARN is required"}), 400

        try:
            client = boto3.client('apigateway', region_name=REGION)
            api_id = api_arn.split(':')[-1]

            # Get all stages for the API
            stages = client.get_stages(restApiId=api_id)

            if not stages['item']:
                return jsonify({"error": "No stages found for this API"}), 400

            # Use the first available stage
            stage_name = stages['item'][0]['stageName']

            try:
                response = client.get_export(
                    restApiId=api_id,
                    stageName=stage_name,
                    exportType='oas30',
                    accepts='application/json'
                )
                open_api_spec = json.loads(response['body'].read().decode('utf-8'))
            except client.exceptions.NotFoundException:
                # If export fails, try to construct a basic OpenAPI spec from the API structure
                resources = client.get_resources(restApiId=api_id)
                open_api_spec = construct_basic_openapi(api_id, resources['items'])

            # Generate rules using the fetched or constructed OpenAPI spec
            waf_rules = generate_rules_from_openapi(json.dumps(open_api_spec), api_context)
            if isinstance(waf_rules, dict) and 'error' in waf_rules:
                return jsonify(waf_rules), 500
            return jsonify({
                "message": f"Generated WAF ACL rules for API Gateway: {api_arn}",
                "rules": json.loads(waf_rules)
            })
        except Exception as e:
            logger.error(f"Error generating WAF rules from API Gateway: {str(e)}", exc_info=True)
            return jsonify({"error": str(e)}), 500

    elif input_type == 'openapi':
        open_api_spec = data.get('open_api_spec')
        if not open_api_spec:
            return jsonify({"error": "OpenAPI Specification is required for OpenAPI input type"}), 400

        try:
            waf_rules = generate_rules_from_openapi(open_api_spec, api_context)
            if isinstance(waf_rules, dict) and 'error' in waf_rules:
                return jsonify(waf_rules), 500
            return jsonify({
                "message": "Generated WAF ACL rules from OpenAPI specification",
                "rules": json.loads(waf_rules)
            })
        except Exception as e:
            logger.error(f"Error generating WAF rules from OpenAPI spec: {str(e)}", exc_info=True)
            return jsonify({"error": str(e)}), 500

    else:
        return jsonify({"error": "Invalid input type. Supported types are 'arn', 'list', and 'openapi'."}), 400

def construct_basic_openapi(api_id, resources):
    paths = {}
    for resource in resources:
        path = resource['path']
        methods = resource.get('resourceMethods', {})
        path_item = {}
        for method in methods:
            if method != 'OPTIONS':
                path_item[method.lower()] = {
                    "responses": {
                        "200": {
                            "description": "Successful response"
                        }
                    }
                }
        if path_item:
            paths[path] = path_item

    return {
        "openapi": "3.0.0",
        "info": {
            "title": f"API {api_id}",
            "version": "1.0.0"
        },
        "paths": paths
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

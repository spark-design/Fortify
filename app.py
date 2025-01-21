import json
import boto3
import logging
import numpy as np
from flask import Flask, jsonify, request, send_from_directory
import re
from botocore.exceptions import ClientError
import yaml


app = Flask(__name__, static_url_path='')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_embedding(text):
    bedrock = boto3.client('bedrock-runtime', region_name='us-east-2')
    response = bedrock.invoke_model(
        modelId='amazon.titan-embed-text-v2:0',
        contentType='application/json',
        accept='application/json',
        body=json.dumps({"inputText": text})
    )
    embedding = json.loads(response['body'].read())['embedding']
    return embedding

def cosine_similarity(a, b):
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

def categorize_endpoint(path, method):
    embedding = get_embedding(f"{path} {method}")
    categories = {
        "user_management": get_embedding("user management authentication"),
        "data_access": get_embedding("data retrieval database access"),
        "admin_operations": get_embedding("admin operations management"),
        "public_content": get_embedding("public content retrieval"),
    }
    similarities = {k: cosine_similarity(embedding, v) for k, v in categories.items()}
    return max(similarities, key=similarities.get)

def generate_ai_enhanced_waf_rules(api_details, resources):
    rules = []
    for resource in resources['items']:
        path = resource['path']
        if 'resourceMethods' in resource:
            for method in resource['resourceMethods']:
                category = categorize_endpoint(path, method)
                
                rules.append({
                    "name": f"Rule for {path} - {method}",
                    "action": "ALLOW",
                    "condition": f"Path is {path} and method is {method}"
                })
                
                if category == "user_management":
                    rules.append({
                        "name": f"Auth Protection for {path}",
                        "action": "BLOCK",
                        "condition": f"Suspicious auth patterns detected for {path}"
                    })
                elif category == "data_access":
                    rules.append({
                        "name": f"Data Protection for {path}",
                        "action": "BLOCK",
                        "condition": f"Unusual data access patterns detected for {path}"
                    })
                elif category == "admin_operations":
                    rules.append({
                        "name": f"Admin Protection for {path}",
                        "action": "BLOCK",
                        "condition": f"Unauthorized admin access attempt on {path}"
                    })
                
                if method == 'POST':
                    rules.append({
                        "name": f"Rate Limit for {path} - POST",
                        "action": "BLOCK",
                        "condition": f"More than 100 requests per 5 minutes from an IP for POST on {path}"
                    })
    
    # Add some general security rules
    rules.extend([
        {
            "name": "SQL Injection Protection",
            "action": "BLOCK",
            "condition": "SQL Injection patterns detected in request parameters"
        },
        {
            "name": "Cross-Site Scripting (XSS) Protection",
            "action": "BLOCK",
            "condition": "XSS patterns detected in request parameters"
        },
        {
            "name": "IP Reputation Check",
            "action": "BLOCK",
            "condition": "Request comes from an IP with bad reputation"
        }
    ])
    
    return rules

@app.route('/')
def home():
    return send_from_directory('static', 'index.html')

def generate_rules_from_openapi(openapi_spec):
    try:
        # Parse the OpenAPI spec
        spec = yaml.safe_load(openapi_spec)
        
        rules = []
        for path, path_item in spec['paths'].items():
            for method, operation in path_item.items():
                category = categorize_endpoint(path, method)

                rules.append({
                    "name": f"Rule for {path} - {method.upper()}",
                    "action": "ALLOW",
                    "condition": f"Path is {path} and method is {method.upper()}"
                })

                if category == "user_management":
                    rules.append({
                        "name": f"Auth Protection for {path}",
                        "action": "BLOCK",
                        "condition": f"Suspicious auth patterns detected for {path}"
                    })
                elif category == "data_access":
                    rules.append({
                        "name": f"Data Protection for {path}",
                        "action": "BLOCK",
                        "condition": f"Unusual data access patterns detected for {path}"
                    })
                elif category == "admin_operations":
                    rules.append({
                        "name": f"Admin Protection for {path}",
                        "action": "BLOCK",
                        "condition": f"Unauthorized admin access attempt on {path}"
                    })

                if method.upper() == 'POST':
                    rules.append({
                        "name": f"Rate Limit for {path} - POST",
                        "action": "BLOCK",
                        "condition": f"More than 100 requests per 5 minutes from an IP for POST on {path}"
                    })

        # Add general security rules
        rules.extend([
            {
                "name": "SQL Injection Protection",
                "action": "BLOCK",
                "condition": "SQL Injection patterns detected in request parameters"
            },
            {
                "name": "Cross-Site Scripting (XSS) Protection",
                "action": "BLOCK",
                "condition": "XSS patterns detected in request parameters"
            },
            {
                "name": "IP Reputation Check",
                "action": "BLOCK",
                "condition": "Request comes from an IP with bad reputation"
            }
        ])

        return rules
    except Exception as e:
        logger.error(f"Error generating WAF rules from OpenAPI spec: {str(e)}", exc_info=True)
        raise

@app.route('/api/generate-rules', methods=['POST'])
def generate_rules():
    data = request.json
    input_type = data.get('input_type')
    context = data.get('context', '')

    if input_type == 'arn':
        api_arn = data.get('api_arn')
        if not api_arn:
            return jsonify({"error": "API ARN is required for ARN input type"}), 400

        try:
            # Extract the API ID from the ARN
            match = re.match(r'arn:aws:execute-api:([^:]+):(\d+):([^/]+)', api_arn)
            if not match:
                return jsonify({"error": "Invalid API ARN format"}), 400

            region, account_id, api_id = match.groups()

            # Initialize the API Gateway client
            client = boto3.client('apigateway', region_name=region)

            try:
                # Get the API details
                api_details = client.get_rest_api(restApiId=api_id)

                # Get the resources for this API
                resources = client.get_resources(restApiId=api_id)

                # Generate WAF rules based on the API structure with AI enhancement
                waf_rules = generate_ai_enhanced_waf_rules(api_details, resources)

                return jsonify({
                    "message": f"Generated AI-enhanced WAF rules for API {api_id}",
                    "api_name": api_details['name'],
                    "rules": waf_rules
                })

            except ClientError as e:
                if e.response['Error']['Code'] == 'NotFoundException':
                    return jsonify({"error": f"API with ID {api_id} not found"}), 404
                else:
                    raise

        except Exception as e:
            logger.error(f"Error generating WAF rules: {str(e)}", exc_info=True)
            return jsonify({"error": str(e)}), 500

    elif input_type == 'openapi':
        open_api_spec = data.get('open_api_spec')
        if not open_api_spec:
            return jsonify({"error": "OpenAPI Specification is required for OpenAPI input type"}), 400

        try:
            waf_rules = generate_rules_from_openapi(open_api_spec)
            return jsonify({
                "message": "Generated AI-enhanced WAF rules from OpenAPI specification",
                "rules": waf_rules
            })
        except Exception as e:
            logger.error(f"Error generating WAF rules from OpenAPI spec: {str(e)}", exc_info=True)
            return jsonify({"error": str(e)}), 500

    else:
        return jsonify({"error": "Invalid input type"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

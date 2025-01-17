import re
import boto3
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_url_path='')

@app.route('/')
def home():
    return send_from_directory('static', 'index.html')

@app.route('/api/generate-rules', methods=['POST'])
def generate_rules():
    api_arn = request.json.get('api_arn')
    if not api_arn:
        return jsonify({"error": "API ARN is required"}), 400

    try:
        # Match different ARN formats
        rest_api_match = re.match(r'arn:aws:apigateway:([^:]+)::/restapis/([^/]+)', api_arn)
        execute_api_match = re.match(r'arn:aws:execute-api:([^:]+):(\d+):([^/]+)', api_arn)

        if rest_api_match:
            region, api_id = rest_api_match.groups()
        elif execute_api_match:
            region, account_id, api_id = execute_api_match.groups()
        else:
            return jsonify({"error": f"Invalid API ARN format. Received: {api_arn}"}), 400

        # Initialize the API Gateway client with the correct region
        client = boto3.client('apigateway', region_name=region)
        
        # Get the API details
        api_details = client.get_rest_api(restApiId=api_id)
        
        # Get the resources for this API
        resources = client.get_resources(restApiId=api_id)
        
        # Generate WAF rules based on the API structure
        waf_rules = []
        for resource in resources['items']:
            path = resource['path']
            if 'resourceMethods' in resource:
                for method in resource['resourceMethods']:
                    waf_rules.append({
                        "name": f"Rule for {path} - {method}",
                        "action": "BLOCK" if method == 'POST' else "ALLOW",
                        "condition": f"Path is {path} and method is {method}"
                    })
        
        return jsonify({
            "message": f"Generated WAF rules for API {api_id}",
            "api_name": api_details['name'],
            "rules": waf_rules
        })

    except client.exceptions.NotFoundException:
        return jsonify({"error": f"API Gateway not found. ARN: {api_arn}"}), 404
    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}. ARN: {api_arn}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

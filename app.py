from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_url_path='')

@app.route('/')
def home():
    return send_from_directory('static', 'index.html')

@app.route('/api/generate-rules', methods=['POST'])
def generate_rules():
    api_id = request.json.get('api_id')
    # Here you would implement your logic to generate WAF rules
    # For now, we'll just return a dummy response
    return jsonify({
        "message": f"Generated WAF rules for API {api_id}",
        "rules": [
            {"id": 1, "name": "Rule 1", "action": "BLOCK"},
            {"id": 2, "name": "Rule 2", "action": "ALLOW"}
        ]
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

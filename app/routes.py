from flask import Blueprint, request, jsonify
from app.model import analyze_url

# Create a blueprint for API routes
api_blueprint = Blueprint('api', __name__)

@api_blueprint.route('/analyze', methods=['POST'])
def analyze():
    """Analyze the given URL for phishing indicators."""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing "url" parameter'}), 400

        url = data['url']
        analysis_result = analyze_url(url)
        return jsonify(analysis_result), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

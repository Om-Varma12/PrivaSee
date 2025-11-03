# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify
from flask_cors import CORS
from url_detector_service import predict_and_score

app = Flask(__name__)
CORS(app)  # Enable CORS for Chrome extension

@app.route("/checkURL", methods=["POST"])
def check_url():
    """
    Endpoint to check if a URL is phishing or legitimate.
    Expects JSON: { "url": "http://example.com" }
    Returns JSON with prediction results and risk assessment.
    """
    data = request.json or {}
    url = data.get("url")
    
    if not url:
        return jsonify({
            "error": True,
            "message": "No URL provided"
        }), 400

    try:
        # Get prediction from the ML model
        result = predict_and_score(url)
        
        # Log the result for debugging
        print(f"\n{'='*60}")
        print(f"URL Checked: {result['url']}")
        print(f"Prediction: {result['prediction']}")
        print(f"Phishing Score: {result['score']}%")
        print(f"Is Phishing: {result['is_phishing']}")
        print(f"{'='*60}\n")
        
        # Prepare response with risk assessment
        risk_level = "low"
        risk_color = "green"
        
        if result['score'] >= 70:
            risk_level = "critical"
            risk_color = "red"
        elif result['score'] >= 50:
            risk_level = "high"
            risk_color = "orange"
        elif result['score'] >= 30:
            risk_level = "medium"
            risk_color = "yellow"
        
        # Generate warnings based on prediction
        warnings = []
        patterns = []
        
        if result['is_phishing']:
            warnings.append("HIGH RISK: This URL has been identified as a phishing attempt")
            patterns.append(f"ML Model confidence: {result['confidence']*100:.1f}%")
        
        if result['score'] >= 50:
            warnings.append("This site may attempt to steal your personal information")
        
        if result['score'] >= 30:
            warnings.append("Exercise caution when entering sensitive data")
        
        # Add feature-based warnings from risk assessment
        if result.get('risk_assessment') and result['risk_assessment'].get('risk_factors'):
            patterns.extend(result['risk_assessment']['risk_factors'])
        
        # Add feature-based warnings
        normalized_url = result['normalized']
        if any(keyword in normalized_url.lower() for keyword in ['login', 'verify', 'account', 'secure', 'banking']):
            patterns.append("Contains suspicious keywords (login, verify, account, etc.)")
        
        # Response format for Chrome extension
        response = {
            "error": False,
            "url": result['url'],
            "normalized": result['normalized'],
            "prediction": result['prediction'],
            "isPhishing": result['is_phishing'],
            "phishingScore": result['score'],  # 0-100 scale
            "confidence": round(result['confidence'] * 100, 2),
            "riskLevel": risk_level,
            "riskColor": risk_color,
            "warnings": warnings,
            "patterns": patterns,
            "probabilities": result['probabilities'],
            "message": f"URL analyzed successfully - Risk Level: {risk_level.upper()}"
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        print(f"Error processing URL: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": True,
            "message": f"Error analyzing URL: {str(e)}",
            "fallback": True
        }), 500


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint to verify the API is running."""
    return jsonify({
        "status": "ok",
        "message": "Phishing detection API is running"
    }), 200


if __name__ == "__main__":
    print("\n" + "="*60)
    print("Starting Phishing Detection API Server")
    print("="*60)
    print("Server running on: http://localhost:5000")
    print("Endpoint: POST http://localhost:5000/checkURL")
    print("Health check: GET http://localhost:5000/health")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
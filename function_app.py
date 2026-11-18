import json
import logging
import azure.functions as func
from enrichment import enrich_alert


app = func.FunctionApp()

@app.route(route="enrich", methods=["POST"])
def enrich(req: func.HttpRequest) -> func.HttpResponse:
    try:
        alert = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body"}),
            status_code=400,
            mimetype="application/json",
        )

    try:
        result = enrich_alert(alert)

        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json",
        )

    except ValueError as e:
        status = 500 if str(e) == "Missing API key" else 400

        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=status,
            mimetype="application/json",
        )

    except Exception:
        logging.exception("Alert enrichment failed")
    
        return func.HttpResponse(
            json.dumps({"error": "Internal server error"}),
            status_code=500,
            mimetype="application/json",
        )
from flask import Flask, render_template
import firebase_admin
from firebase_admin import credentials, firestore
from collections import Counter

app = Flask(__name__)

# Initialize Firebase
cred = credentials.Certificate('fbdatabase.json')
firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()

@app.route('/')
def index():
    # Get data from Firestore
    logs_collection = db.collection('Logs')
    log_documents = logs_collection.stream()
    
    # Count the number of logs by category (e.g. "Application", "Security")
    log_counts = Counter()
    total_log_entries = 0
    
    for log_document in log_documents:
        document_name = log_document.id
        entries = logs_collection.document(document_name).collection('Entries').stream()
        entry_count = sum(1 for _ in entries)
        log_counts[document_name] = entry_count
        total_log_entries += entry_count
        
    return render_template('index.html', log_counts=log_counts, total_log_entries=total_log_entries)

if __name__ == '__main__':
    app.run(debug=True)

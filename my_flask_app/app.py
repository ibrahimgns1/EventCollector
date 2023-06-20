from flask import Flask, render_template
import firebase_admin
from firebase_admin import credentials, firestore
from collections import Counter
from flask_paginate import Pagination, get_page_parameter
from flask import request

app = Flask(__name__)

# Initialize Firebase
cred = credentials.Certificate('fbdatabase.json')
firebase_admin.initialize_app(cred)

# Initialize Firestore
db = firestore.client()
class LogEntry:
    def __init__(self, id, category, message):
        self.id = id
        self.category = category
        self.message = message

def get_log_entries(category):
    entries = []
    logs_collection = db.collection('Logs')
    entry_documents = logs_collection.document(category).collection('Entries').stream()
    for entry_document in entry_documents:
        data = entry_document.to_dict()
        log_entry = {
            'LogName': data.get('LogName', ''),
            'RecordNumber': data.get('RecordNumber', ''),
            'EventID': data.get('EventID', ''),
            'EventType': data.get('EventType', ''),
            'SourceName': data.get('SourceName', ''),
            'ComputerName': data.get('ComputerName', ''),
            'Category': data.get('Category', ''),
            'TimeGenerated': data.get('TimeGenerated', ''),
            'TimeWritten': data.get('TimeWritten', ''),
            'Message': data.get('Message', '')
        }
        entries.append(log_entry)
    return entries


from flask import render_template, request
from math import ceil

@app.route('/category/<category>')
def category(category):
    page = request.args.get('page', 1, type=int)
    per_page = 10

    entries = get_log_entries(category)

    total_entries = len(entries)
    total_pages = ceil(total_entries / per_page)
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    paginated_entries = entries[start_index:end_index]

    pagination = {
        'page': page,
        'pages': total_pages,
        'per_page': per_page,
        'total_entries': total_entries,
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'prev_num': page - 1 if page > 1 else None,
        'next_num': page + 1 if page < total_pages else None,
        'page_range': range(1, total_pages + 1),
    }

    return render_template('category.html', category=category, entries=paginated_entries, pagination=pagination)




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

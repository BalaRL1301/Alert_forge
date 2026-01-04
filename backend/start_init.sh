#!/bin/bash
# Kill existing processes on ports
lsof -ti:5140 | xargs kill -9 2>/dev/null
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:5001 | xargs kill -9 2>/dev/null

source venv/bin/activate

echo "Starting Log Collector..."
python log_collector.py &
PID_COLLECTOR=$!

echo "Starting Vulnerable App..."
python vulnerable_app.py &
PID_APP=$!

echo "Starting Detection API..."
uvicorn api:app --host 0.0.0.0 --port 8000 &
PID_API=$!

echo "Backend Services Started."
echo "Collector PID: $PID_COLLECTOR"
echo "App PID: $PID_APP"
echo "API PID: $PID_API"

wait

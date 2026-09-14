import json

def handle(message):
    task = json.loads(message.body)
    return run_task(task)

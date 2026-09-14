import pickle

def handle(message):
    task = pickle.loads(message.body)
    return task.run()

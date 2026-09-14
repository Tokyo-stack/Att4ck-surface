import yaml

def parse(stream):
    return yaml.safe_load(stream)

"""Check workflow YAML without constructing objects from its tags."""

import sys

import yaml


def valid_workflow(source):
    try:
        root = yaml.compose(source, Loader=yaml.BaseLoader)
    except (yaml.YAMLError, RecursionError):
        return False
    if not isinstance(root, yaml.MappingNode):
        return False

    pending = [root]
    seen = set()
    while pending:
        node = pending.pop()
        if node in seen:
            continue
        seen.add(node)
        if isinstance(node, yaml.MappingNode):
            keys = set()
            for key, value in node.value:
                if not isinstance(key, yaml.ScalarNode) or key.value in keys:
                    return False
                keys.add(key.value)
                pending.append(value)
        elif isinstance(node, yaml.SequenceNode):
            pending.extend(node.value)
    return True


if __name__ == "__main__":
    raise SystemExit(0 if valid_workflow(sys.stdin) else 1)

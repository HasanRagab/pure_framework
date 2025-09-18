import inspect

def convert_type(value, to_type):
    if to_type == bool:
        if isinstance(value, str):
            return value.lower() in ("true", "1", "yes")
        return bool(value)
    try:
        return to_type(value)
    except (ValueError, TypeError):
        raise ValueError(f"Cannot convert {value} to {to_type}")

def inject_params(func, req):
    sig = inspect.signature(func)
    kwargs = {}
    for name, param in sig.parameters.items():
        if name == "self":
            continue

        value = None
        if name in req.params:
            value = req.params[name]
        elif name in req.query:
            value = req.query[name]
        elif param.default != inspect.Parameter.empty:
            value = param.default
        else:
            value = None

        if param.annotation != inspect.Parameter.empty and value is not None:
            value = convert_type(value, param.annotation)
        kwargs[name] = value
    return kwargs

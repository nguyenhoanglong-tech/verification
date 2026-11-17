def add(a, b):
    return a + b


def safe_div(a, b):
    if b == 0:
        raise ZeroDivisionError("b must not be zero")
    return a / b

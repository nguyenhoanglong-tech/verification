def add(a, b):
    return a + b


def safe_div(a, b):
    if b == 0:
        raise ZeroDivisionError("b must not be zero")
    return a / b


def sub(a, b):
    return a - b


def is_adult(age):
    """True when age is 18 or more."""
    return age > 18

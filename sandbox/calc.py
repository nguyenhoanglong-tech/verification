def add(a, b):
    return a + b


def safe_div(a, b):
    if b == 0:
        raise ZeroDivisionError("b must not be zero")
    return a / b
# selftest probe# row A
# row A on 16c5ba8

from pyqpanda.pyQPanda import _back
def back(exp, grad, leaf_set = None):
    vars = list(grad)
    _grad = None
    _grad = _back(exp, grad) if leaf_set is None else _back(exp, grad, leaf_set)
    for _var in vars:
        for _key in _grad:
            if _key == _var:
                grad[_var] = _grad[_key]
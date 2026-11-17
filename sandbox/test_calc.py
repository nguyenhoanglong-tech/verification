import unittest

from calc import add, safe_div


class Calc(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_div(self):
        self.assertEqual(safe_div(6, 3), 2)
        with self.assertRaises(ZeroDivisionError):
            safe_div(1, 0)


if __name__ == "__main__":
    unittest.main()

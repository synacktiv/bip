import pytest

pytest.main([r"test_bipelt.py",  "--capture=sys"])
pytest.main([r"test_bipinstr.py",  "--capture=sys"])
pytest.main([r"test_enum.py",  "--capture=sys"])
pytest.main([r"test_bipfunc.py",  "--capture=sys"])
pytest.main([r"test_bipstruct.py",  "--capture=sys"])
pytest.main([r"test_hx_base.py",  "--capture=sys"])
pytest.main([r"test_bipblock.py",  "--capture=sys"])


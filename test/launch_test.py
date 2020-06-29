import pytest


## Base
pytest.main([r"test_bipelt.py",  "--capture=sys"])
pytest.main([r"test_bipinstr.py",  "--capture=sys"])
pytest.main([r"test_enum.py",  "--capture=sys"])
pytest.main([r"test_bipfunc.py",  "--capture=sys"])
pytest.main([r"test_bipstruct.py",  "--capture=sys"])
pytest.main([r"test_bipblock.py",  "--capture=sys"])
pytest.main([r"test_bipdata.py",  "--capture=sys"])
pytest.main([r"test_biptype.py",  "--capture=sys"])
pytest.main([r"test_bipxref.py",  "--capture=sys"])
pytest.main([r"test_bipoperand.py",  "--capture=sys"])
pytest.main([r"test_biputils.py",  "--capture=sys"])

## Gui
pytest.main([r"test_bipactivity.py",  "--capture=sys"])
pytest.main([r"test_menutb.py",  "--capture=sys"])
pytest.main([r"test_bipaction.py",  "--capture=sys"])
pytest.main([r"test_bipplugin.py",  "--capture=sys"])

## Hexrays
pytest.main([r"test_hxcfunc.py",  "--capture=sys"])
pytest.main([r"test_hx_base.py",  "--capture=sys"])

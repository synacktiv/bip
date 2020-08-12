import pytest
import sys

## Setup Python3/IDA for pytest

if sys.version_info[0] == 3:
    import io, tempfile
    # IDA replace sys.__stderr__ by None when in python 3
    sys.__stderr__ = io.TextIOWrapper(tempfile.TemporaryFile())


## Base
pytest.main([r"test_bipidb.py",  "--capture=sys"])
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

## Gui
pytest.main([r"test_bipactivity.py",  "--capture=sys"])
pytest.main([r"test_menutb.py",  "--capture=sys"])
pytest.main([r"test_bipaction.py",  "--capture=sys"])
pytest.main([r"test_bipplugin.py",  "--capture=sys"])
pytest.main([r"test_bipuserselect.py",  "--capture=sys"])

## Hexrays
pytest.main([r"test_hxcfunc.py",  "--capture=sys"])
pytest.main([r"test_hxlvar.py",  "--capture=sys"])
pytest.main([r"test_astnode.py",  "--capture=sys"])

## Clean Python3/IDA for pytest

if sys.version_info[0] == 3:
    sys.__stderr__ = None



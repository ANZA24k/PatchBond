import pytest
from clamp import clamp

@pytest.mark.parametrize('value,lower,upper,expected', [
    (-1,0,5,0),(0,0,5,0),(3,0,5,3),(5,0,5,5),(9,0,5,5),
    (-10,-5,-1,-5),(-5,-5,-1,-5),(-3,-5,-1,-3),(-1,-5,-1,-1),(0,-5,-1,-1),
    (-10,2,2,2),(2,2,2,2),(10,2,2,2),(-100,-10,10,-10),(100,-10,10,10)])
def test_inclusive_behavior(value,lower,upper,expected):
    assert clamp(value,lower,upper)==expected

@pytest.mark.parametrize('value,lower,upper',[(0,3,2),(-100,0,-1),(100,10,-10),(2,2,1)])
def test_reversed_bounds(value,lower,upper):
    with pytest.raises(ValueError): clamp(value,lower,upper)

def test_exhaustive_small_integer_properties():
    for lower in range(-4,5):
        for upper in range(lower,5):
            for value in range(-8,9):
                result=clamp(value,lower,upper)
                assert lower<=result<=upper
                assert result==(lower if value<lower else upper if value>upper else value)
                assert clamp(result,lower,upper)==result

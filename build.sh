rm -rvf dist
python -m build
twine upload dist/*
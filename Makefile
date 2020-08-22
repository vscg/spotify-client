clean-build:
	@echo "Removing build artifacts"
	rm -rf dist/
	rm -rf build/
	rm -rf spotify_client.egg-info/

clean-tests:
	@echo "Removing test artifacts"
	rm -rf htmlcov/
	rm -f .coverage

build:
	python setup.py sdist bdist_wheel

upload:
	twine upload dist/*

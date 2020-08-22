clean-build:
	@echo "Removing build artifacts"
	rm -rf dist/
	rm -rf build/
	rm -rf spotify_client.egg-info/

build:
	python setup.py sdist bdist_wheel

upload:
	twine upload dist/*

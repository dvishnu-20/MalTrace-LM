.PHONY: help install test analyze-example dashboard lint clean

help:
	@echo "MalTrace-LM Makefile Commands:"
	@echo "  make install         Install package in editable mode"
	@echo "  make test            Run test suite with pytest"
	@echo "  make analyze-example Analyze default sample trace via CLI"
	@echo "  make dashboard       Launch Streamlit interactive dashboard"
	@echo "  make clean           Clean build and cache artifacts"

install:
	pip install -e .

test:
	pytest -v

analyze-example:
	python -m maltrace analyze data/samples/example.json --out reports/example.json

dashboard:
	streamlit run src/maltrace/dashboard/app.py

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache/ __pycache__

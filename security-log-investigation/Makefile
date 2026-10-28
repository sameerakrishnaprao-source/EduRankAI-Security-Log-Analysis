.PHONY: logs analyze test
logs:     ## regenerate the synthetic sample logs
	python3 generate_sample_logs.py
analyze:  ## parse logs and write findings/analysis_output.txt
	python3 analyze_logs.py
test:     ## run unit tests
	python3 -m unittest discover -s . -v

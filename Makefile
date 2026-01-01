.PHONY: run clean

run:
	python3 main.py debian-netinst-test.torrent

clean:
	rm -f *.pyc
	rm -rf __pycache__

.DEFAULT_GOAL:all

.PHONY: all
all: fresh

fresh: down up

.PHONY:up
up:
	@docker-compose -f docker-compose.yaml up --build

.PHONY:down
down:
	@docker-compose -f docker-compose.yaml down

.PHONY: commit
commit:
	@git add .
	@git commit -am "postgres proxy"
	@git push

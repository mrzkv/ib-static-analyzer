#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Установка astguard ===${NC}"

# Проверка наличия python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Ошибка: python3 не найден. Пожалуйста, установите Python 3.8 или выше.${NC}"
    exit 1
fi

# Проверка версии python
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [[ $(echo -e "$PYTHON_VERSION\n3.8" | sort -V | head -n1) != "3.8" ]]; then
    echo -e "${RED}Ошибка: Требуется Python версии 3.8 или выше. У вас установлена версия $PYTHON_VERSION.${NC}"
    exit 1
fi

# Проверка наличия git
if ! command -v git &> /dev/null; then
    echo -e "${RED}Ошибка: git не найден. Пожалуйста, установите git.${NC}"
    exit 1
fi

# Попытка установки через uv или pip из репозитория GitHub
REPO_URL="git+https://github.com/mrzkv/ib-static-analyzer.git"

echo -e "${BLUE}Установка пакета...${NC}"

# 1. Пытаемся через uv (если есть)
if command -v uv &> /dev/null; then
    if uv pip install "$REPO_URL" ; then
        echo -e "${GREEN}Установка через uv завершена успешно!${NC}"
        echo -e "Теперь вы можете использовать команду: ${BLUE}astguard --help${NC}"
        exit 0
    fi
fi

# 2. Пытаемся через pipx (рекомендуемый способ для CLI инструментов)
if command -v pipx &> /dev/null; then
    if pipx install "$REPO_URL" --force ; then
        echo -e "${GREEN}Установка через pipx завершена успешно!${NC}"
        echo -e "Теперь вы можете использовать команду: ${BLUE}astguard --help${NC}"
        exit 0
    fi
fi

# 3. Пытаемся через обычный pip
PIP_ARGS=""
if python3 -m pip install --help | grep -q "break-system-packages"; then
    PIP_ARGS="--break-system-packages"
fi

if python3 -m pip install "$REPO_URL" $PIP_ARGS ; then
    echo -e "${GREEN}Установка через pip завершена успешно!${NC}"
    echo -e "Теперь вы можете использовать команду: ${BLUE}astguard --help${NC}"
else
    echo -e "${RED}Ошибка при установке. Попробуйте установить pipx или использовать виртуальное окружение.${NC}"
    exit 1
fi

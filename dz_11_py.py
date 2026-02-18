import json
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# 1. Загрузка и подготовка данных
win_file = 'botsv1.json'
if not os.path.exists(win_file):
    raise FileNotFoundError(f"Файл {win_file} не найден в текущей директории.")

with open(win_file, 'r', encoding='utf-8') as f:
    win_data = json.load(f)

# Извлечение полей result
win_records = [item['result'] for item in win_data]
df_win = pd.DataFrame(win_records)

# Нормализация: преобразование списков в строки (если есть)
for col in df_win.columns:
    if df_win[col].apply(lambda x: isinstance(x, list)).any():
        df_win[col] = df_win[col].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)

print("WinEventLog загружен. Размер:", df_win.shape)

# Попытка загрузки DNS-логов (если файл существует)

dns_file = 'botsv1.json' 
if os.path.exists(dns_file):
    if dns_file.endswith('.json'):
        with open(dns_file, 'r', encoding='utf-8') as f:
            dns_data = json.load(f)
        # Предполагаем, что структура аналогична или извлекаем записи
        if isinstance(dns_data, list):
            df_dns = pd.DataFrame(dns_data)
        else:
            # Если это словарь с ключом 'result'
            if 'result' in dns_data:
                df_dns = pd.DataFrame(dns_data['result'])
            else:
                df_dns = pd.DataFrame([dns_data])
    elif dns_file.endswith('.csv'):
        df_dns = pd.read_csv(dns_file)
    else:
        print("Неизвестный формат DNS-логов, пропускаем.")
    print("DNS-логи загружены. Размер:", df_dns.shape if df_dns is not None else "N/A")
else:
    print("Файл с DNS-логами не найден. Анализ будет выполнен только для WinEventLog.")

# 2. Определение подозрительных событий

# Список подозрительных EventID (можно расширить)
suspicious_eventids = ['4624', '4625', '4672', '4688', '4689', '4698', '4703', '4656']

# Подсчёт количества для каждого EventID (только подозрительные)
win_counts = df_win['EventCode'].value_counts()
win_suspicious = win_counts[win_counts.index.isin(suspicious_eventids)].reset_index()
win_suspicious.columns = ['EventID', 'Count']
win_suspicious['Source'] = 'Windows'

print("Подозрительные события Windows (по EventID):")
print(win_suspicious)

# 3. Анализ DNS-логов (если доступны)

dns_suspicious = pd.DataFrame()
if df_dns is not None:
    # Пример анализа DNS: ищем частые запросы к доменам с подозрительными TLD или длинными именами
    # Предположим, что в DNS-логах есть поле 'query' (доменное имя)
    if 'query' in df_dns.columns:
        # Удалим пустые и нормализуем
        queries = df_dns['query'].dropna().astype(str).str.lower()
        
        # Пример 1: самые частые домены 
        top_domains = queries.value_counts().head(20)
        н
        # Пример 2: подозрительные TLD 
        suspicious_tlds = ['.xyz', '.top', '.bid', 'download', '.science', '.win']
        mask_tld = queries.str.endswith(tuple(suspicious_tlds), na=False)
        tld_queries = queries[mask_tld]
        tld_counts = tld_queries.value_counts().head(10).reset_index()
        tld_counts.columns = ['Domain', 'Count']
        tld_counts['Source'] = 'DNS (suspicious TLD)'
        
        # Пример 3: домены с длиной > 50 символов
        long_queries = queries[queries.str.len() > 50]
        long_counts = long_queries.value_counts().head(10).reset_index()
        long_counts.columns = ['Domain', 'Count']
        long_counts['Source'] = 'DNS (long name)'
        
        # Объединяем все подозрительные DNS-события
        dns_suspicious = pd.concat([tld_counts, long_counts], ignore_index=True)
        print("Подозрительные DNS-запросы:")
        print(dns_suspicious)
    else:
        print("В DNS-логах нет поля 'query'. Анализ невозможен.")

# 4. Объединение результатов и построение топ-10

# Объединяем Windows и DNS (если есть) в один DataFrame для визуализации
combined = win_suspicious.copy()
if not dns_suspicious.empty:
    # Переименуем колонки для единообразия
    dns_suspicious = dns_suspicious.rename(columns={'Domain': 'EventID'})
    combined = pd.concat([combined, dns_suspicious], ignore_index=True, sort=False)

# Сортируем по убыванию и берём топ-10
top10 = combined.sort_values('Count', ascending=False).head(10)

# Если DNS-логов нет, то топ-10 берётся из Windows
print("Топ-10 подозрительных событий:")
print(top10)

# 5. Визуализация
plt.figure(figsize=(12, 6))
sns.barplot(data=top10, x='EventID', y='Count', hue='Source', dodge=False, palette='viridis')
plt.title('Топ-10 подозрительных событий в логах')
plt.xlabel('Событие / Домен')
plt.ylabel('Количество')
plt.xticks(rotation=45, ha='right')
plt.legend(title='Источник')
plt.tight_layout()
plt.savefig('top10_suspicious.png', dpi=150)
plt.show()

print("График сохранён как 'top10_suspicious.png'")
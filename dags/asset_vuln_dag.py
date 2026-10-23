"""Airflow DAG: refresh vulnerability attribution every 6 hours."""
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator

from src import pipeline

with DAG(
    dag_id="asset_vulnerability_attribution",
    start_date=datetime(2026, 10, 1),
    schedule="0 */6 * * *",
    catchup=False,
    default_args={"retries": 2, "retry_delay": timedelta(minutes=5)},
    tags=["security", "attribution"],
) as dag:
    PythonOperator(task_id="run_pipeline", python_callable=pipeline.run)

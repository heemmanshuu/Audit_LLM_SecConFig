import asyncio
import copy
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal, Optional, Tuple, Union

import cutie
import fire
import pandas as pd
import yaml
from dotenv import load_dotenv
from groq import APIStatusError
from langchain_anthropic import ChatAnthropic
from langchain_community.callbacks import UpstashRatelimitError, UpstashRatelimitHandler
from langchain_community.llms import VLLM, VLLMOpenAI
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.rate_limiters import InMemoryRateLimiter
from langchain_core.runnables import RunnableLambda, RunnableParallel
from langchain_groq import ChatGroq
from langchain_mistralai import ChatMistralAI
from langchain_openai import ChatOpenAI
from openai import RateLimitError
from tqdm.asyncio import tqdm as async_tqdm
from tqdm.rich import tqdm
from upstash_ratelimit import FixedWindow, Ratelimit
from upstash_redis import Redis

from vendors import Checkov, YAMLTextOutputParser

def convert_chat_to_prompt(chat_template: ChatPromptTemplate) -> PromptTemplate:
    messages = chat_template.messages
    tmp = []
    for _m in messages:
        tmp.append(_m.prompt.template)
    prompt_template = PromptTemplate.from_template("\n".join(tmp))
    return prompt_template

def load_test_data(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def test_loader(testset):
    for item in testset:
        file_name = item["files"]
        ids = item["results"]
        with open(file_name, "r") as f:
            yamls = yaml.load_all(f.read(), Loader=yaml.FullLoader)
        for idx, yaml_data in enumerate(yamls):
            if idx in ids:
                yield file_name, idx, yaml_data

def load_or_create_test_result(csv_path):
    if os.path.exists(csv_path):
        return pd.read_csv(csv_path)
    return pd.DataFrame(columns=["file", "ids", "step_id", "passes"])

def process_test_item(sat: Any, chain: Any, file_name: str, idx: int, test_item: Any, save_result_dir: Path, llm_name: str, retry: int, df: Any, PARSE_RETRY) -> Optional[Dict[str, Any]]:
    base_name = f"{Path(file_name).stem}---{llm_name}_{idx}"
    json_file = save_result_dir / f"{base_name}.json"
    yaml_file = save_result_dir / f"{base_name}.yaml"
    if json_file.exists() and yaml_file.exists():
        matching_row = df[(df["file"] == file_name) & (df["ids"] == idx)]
        if not matching_row.empty:
            passes = matching_row["passes"].iloc[0]
            step_id = matching_row["step_id"].iloc[0]
            if passes or (not passes and step_id + 1 >= retry):
                return None

    try:
        fixed, res, step_id, passed = sat.fix([test_item], chain, retry, PARSE_RETRY)
        if fixed:
            sat.dump_yaml_to_file(fixed, str(yaml_file))
        sat.dump_json_to_file(res, str(json_file))
        return {"file": file_name, "ids": idx, "step_id": step_id, "passes": passed}
    except (RateLimitError, UpstashRatelimitError, APIStatusError) as e:
        print(f"Rate limit exceeded: {e}")
        raise e
    except Exception as e:
        print(f"Error processing {file_name}: {e}")
        return None

async def process_test_item_async(sat: Any, chain: Any, file_name: str, idx: int, test_item: Any, save_result_dir: Path, llm_name: str, retry: int, df: Any, PARSE_RETRY) -> Optional[Dict[str, Any]]:
    base_name = f"{Path(file_name).stem}---{llm_name}_{idx}"
    json_file = save_result_dir / f"{base_name}.json"
    yaml_file = save_result_dir / f"{base_name}.yaml"

    if json_file.exists() and yaml_file.exists():
        matching_row = df[(df["file"] == file_name) & (df["ids"] == idx)]
        if not matching_row.empty:
            passes = matching_row["passes"].iloc[0]
            step_id = matching_row["step_id"].iloc[0]
            if passes or (not passes and step_id + 1 >= retry):
                return None

    try:
        fixed, res, step_id, passed = await sat.afix([test_item], chain, retry, PARSE_RETRY)
        if fixed:
            sat.dump_yaml_to_file(fixed, str(yaml_file))
        sat.dump_json_to_file(res, str(json_file))
        return {"file": file_name, "ids": idx, "step_id": step_id, "passes": passed}
    except (RateLimitError, UpstashRatelimitError, APIStatusError) as e:
        print(f"Rate limit exceeded: {e}")
        raise e
    except Exception as e:
        print(f"Error processing {file_name}: {e}")
        return None

def update_test_result(test_result, new_data, csv_path):
    if new_data:
        new_row = pd.DataFrame([new_data])
        test_result = pd.concat([test_result, new_row], ignore_index=True)
        test_result.drop_duplicates(subset=["file", "ids"], keep="last", inplace=True)
        test_result.to_csv(csv_path, index=False)
    return test_result

async def async_main(sat, chain, testset, test_result, SAVE_RESULT_DIR, LLM_NAME, RETRY, MAX_NUM, CSV_PATH, CONCURRENCY, PARSE_RETRY):
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def process_with_semaphore(file_name, idx, test_item):
        async with semaphore:
            return await process_test_item_async(sat, chain, file_name, idx, test_item, SAVE_RESULT_DIR, LLM_NAME, RETRY, test_result, PARSE_RETRY)
    tasks = [process_with_semaphore(file_name, idx, test_item) for file_name, idx, test_item in test_loader(testset)]

    results = []
    for result in async_tqdm(asyncio.as_completed(tasks), total=min(len(tasks), MAX_NUM)):
        try:
            new_data = await result
            if new_data:
                test_result = update_test_result(test_result, new_data, CSV_PATH)
                results.append(new_data)
        except (RateLimitError, UpstashRatelimitError) as e:
            print(f"Rate limit exceeded: {e}")
            break
        except Exception as e:
            print(f"Error processing task: {e}")

    print(f"Processed {len(results)} items successfully")

def sync_main(sat, chain, testset, test_result, SAVE_RESULT_DIR, LLM_NAME, RETRY, MAX_NUM, CSV_PATH, PARSE_RETRY):
    for file_name, idx, test_item in tqdm(test_loader(testset), total=MAX_NUM):
        try:
            new_data = process_test_item(sat, chain, file_name, idx, test_item, SAVE_RESULT_DIR, LLM_NAME, RETRY, test_result, PARSE_RETRY)
            test_result = update_test_result(test_result, new_data, CSV_PATH)
        except (RateLimitError, UpstashRatelimitError) as e:
            print(f"Rate limit exceeded: {e}")
            break
        except Exception as e:
            print(f"Error processing task: {e}")

class LLM:
    def __init__(self, name: str, vendor: str, rpm: Optional[int] = None, tpm: Optional[int] = None, rps: Optional[float] = None):
        self.name = name
        self.vendor = vendor
        self.rpm = rpm
        self.tpm = tpm
        self.rps = rps

    def setup_rate_limit_handler(self, LLM_NAME, rpm=None, tpm=None):
        load_dotenv()
        assert rpm or tpm, "rpm or tpm should be provided"
        redis_cli = Redis.from_env()
        # initialize ratelimit variables
        request_ratelimit = None
        token_ratelimit = None

        # create ratelimit
        if rpm:
            request_ratelimit = Ratelimit(
                redis=redis_cli,
                limiter=FixedWindow(max_requests=rpm, window=60),
            )
        if tpm:
            token_ratelimit = Ratelimit(
                redis=redis_cli,
                limiter=FixedWindow(max_requests=tpm, window=60),
            )

        # create handler
        user_id = LLM_NAME  # should be a method which gets the user id
        handler = UpstashRatelimitHandler(identifier=user_id, request_ratelimit=request_ratelimit, token_ratelimit=token_ratelimit)
        return handler

    def setup_rate_limiter(self, rps=None, rpm=None, check_every_n_seconds=0.1, max_bucket_size=10):
        assert rps or rpm, "rps or rpm should be provided"
        rate_limiter = InMemoryRateLimiter(
            requests_per_second=rps if rps else rpm / 60,  # <-- Super slow! We can only make a request once every 10 seconds!!
            check_every_n_seconds=check_every_n_seconds,  # Wake up every 100 ms to check whether allowed to make a request,
            max_bucket_size=max_bucket_size,  # Controls the maximum burst size.
        )
        return rate_limiter

class LLMs:
    model_list: List[LLM] = [
        LLM(name="gpt-4o-mini", vendor="openai"),
        LLM(name="claude-3-5-sonnet", vendor="anthropic"),
        LLM(name="llama-3.1-70b-versatile", vendor="groq", rpm=30, tpm=6000),
        LLM(name="hermes3-70b", vendor="lambda"),
        LLM(name="mistral-large-2407", vendor="mistral", tpm=500000, rps=1),
        LLM(name="hermes-3-llama-3.1-405b-fp8-128k", vendor="lambda"),
        LLM(name="Qwen/Qwen2.5-72B-Instruct-AWQ", vendor="vllm"),
    ]

    def get_models_name_list(self):
        return [llm.name for llm in self.model_list]

    def get_llm(self, name):
        for llm in self.model_list:
            if llm.name == name:
                return llm
        return None

    def create_llm(self, llm, temperature=0.5):
        handler = None
        rate_limiter = None
        if any([llm.rpm, llm.rps, llm.tpm]):
            # handler = llm.setup_rate_limit_handler(llm.name, llm.rpm, llm.tpm)
            rate_limiter = llm.setup_rate_limiter(llm.rps, llm.rpm)
        return self._setup_model(llm, temperature, handler=handler, rate_limiter=rate_limiter)

    def _setup_model(self, llm: LLM, temperature=0.5, handler: Optional[Any] = None, rate_limiter: Optional[Any] = None):
        load_dotenv()
        match llm.vendor:
            case "groq" | "lambda" | "openai" | "anthropic" | "mistral":
                # return ChatOpenAI(
                #     model=llm.name, temperature=temperature, rate_limiter=rate_limiter, callbacks=[handler] if handler else None, openai_api_base="http://0.0.0.0:4000", api_key="sk-1234"
                # )
                return ChatOpenAI(model=llm.name, temperature=temperature, openai_api_base="http://0.0.0.0:4000", api_key="sk-1234")
            case "mistral":
                return ChatMistralAI(model=llm.name, temperature=temperature, rate_limiter=rate_limiter, callbacks=[handler] if handler else None)
                # return ChatOpenAI(
                #         model=llm.name, temperature=temperature, rate_limiter=rate_limiter, callbacks=[handler] if handler else None, openai_api_base="http://0.0.0.0:4000", api_key="sk-1234"
                #     )
            case "vllm":
                return VLLMOpenAI(
                    model=llm.name,
                    openai_api_key="token-abc123",
                    openai_api_base="http://localhost:8000/v1",
                    temperature=temperature,
                    frequency_penalty=1.0,
                    max_tokens=8192,
                    request_timeout=60 * 10,
                )
                # return VLLM(
                #     model=llm.name,
                #     trust_remote_code=True,
                #     temperature=temperature,
                #     tensor_parallel_size=2,
                #     max_new_tokens=8192,
                #     vllm_kwargs=dict(pipeline_parallel_size=1, quantization="awq_marlin", gpu_memory_utilization=1, device="cuda", disable_custom_all_reduce=True, enforce_eager=True),
                # )
            case _:
                raise ValueError("Invalid vendor")

def run(use_async=False, concurrency=3, mode: Literal["all", "raw", "code", "prisma"] = "all"):
    load_dotenv()
    # create a console selection for choosing the LLM
    llms = LLMs()
    name_list = llms.get_models_name_list()
    print("Choose the LLM:")
    LLM_NAME = name_list[cutie.select(name_list)]
    RETRY = 10
    PARSE_RETRY = 5
    MAX_NUM = 1000
    match mode:
        case "all":
            SAVE_DIR = Path("test")
        case "raw" | "code" | "prisma":
            SAVE_DIR = Path(f"test_{mode}")
        case _:
            raise ValueError("Invalid mode")
    SAVE_RESULT_DIR = SAVE_DIR / Path("checkov")
    CSV_PATH = SAVE_RESULT_DIR / Path(f"checkov_{LLM_NAME}.csv")

    os.makedirs(SAVE_RESULT_DIR, exist_ok=True)

    testset = load_test_data("fetch_artifacthub/gathered/top_1000_split_files.json")
    # testset = testset[::-1]
    model = llms.create_llm(llms.get_llm(LLM_NAME))

    sat = Checkov(mode=mode)
    if LLM_NAME == "claude-3-5-sonnet":
        pt = convert_chat_to_prompt(sat.template)
        completion_chain = pt | model
    else:
        completion_chain = sat.template | model

    chain = completion_chain | YAMLTextOutputParser()

    test_result = load_or_create_test_result(CSV_PATH)

    if use_async:
        asyncio.run(async_main(sat, chain, testset, test_result, SAVE_RESULT_DIR, LLM_NAME, RETRY, MAX_NUM, CSV_PATH, concurrency, PARSE_RETRY))
    else:
        sync_main(sat, chain, testset, test_result, SAVE_RESULT_DIR, LLM_NAME, RETRY, MAX_NUM, CSV_PATH, PARSE_RETRY)

if __name__ == "__main__":
    fire.Fire(run)

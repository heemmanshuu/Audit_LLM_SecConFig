# set env variables
import os

os.environ["UPSTASH_REDIS_REST_URL"] = "****"
os.environ["UPSTASH_REDIS_REST_TOKEN"] = "****"
os.environ["OPENAI_API_KEY"] = "****"

from langchain_community.callbacks import UpstashRatelimitError, UpstashRatelimitHandler
from langchain_core.runnables import RunnableLambda
from langchain_openai import ChatOpenAI
from upstash_ratelimit import FixedWindow, Ratelimit
from upstash_redis import Redis

# create ratelimit
ratelimit = Ratelimit(
    redis=Redis.from_env(),
    # 500 tokens per window, where window size is 60 seconds:
    limiter=FixedWindow(max_requests=500, window=60),
)

# create handler
user_id = "user_id"  # should be a method which gets the user id
# handler = UpstashRatelimitHandler(identifier=user_id, token_ratelimit=ratelimit, request_ratelimit=)
handler = UpstashRatelimitHandler(identifier=user_id, token_ratelimit=ratelimit)

# create mock chain
as_str = RunnableLambda(str)
model = ChatOpenAI()

chain = as_str | model

# invoke chain with handler:
try:
    result = chain.invoke("Hello world!", config={"callbacks": [handler]})
except UpstashRatelimitError:
    print("Handling ratelimit.", UpstashRatelimitError)

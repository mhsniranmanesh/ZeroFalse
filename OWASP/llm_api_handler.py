#!/usr/bin/env python3
"""
LLM API Handler Module
Handles all interactions with OpenAI API and OpenRouter for security analysis.
Supports model-specific parameters and configurations.
"""

import os
import sys
import tiktoken
from openai import OpenAI

# Model pricing information
MODEL_PRICING = {
    # OpenAI Models
    "gpt-5": {
        "input": 0.00125,  # $1.25 per 1M tokens = $0.00125 per 1K tokens for input
        "output": 0.01     # $10 per 1M tokens = $0.01 per 1K tokens for output
    },
    "gpt-4": {
        "input": 0.03,  # $0.03 per 1K tokens for input
        "output": 0.06  # $0.06 per 1K tokens for output
    },
    "gpt-4-turbo": {
        "input": 0.01,  # $0.01 per 1K tokens for input
        "output": 0.03  # $0.03 per 1K tokens for output
    },
    "gpt-4o": {
        "input": 0.005,  # $0.005 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    "gpt-4-turbo-preview": {
        "input": 0.01,  # $0.01 per 1K tokens for input
        "output": 0.03  # $0.03 per 1K tokens for output
    },
    "gpt-3.5-turbo": {
        "input": 0.001,  # $0.001 per 1K tokens for input
        "output": 0.002  # $0.002 per 1K tokens for output
    },
    "gpt-3.5-turbo-instruct": {
        "input": 0.0015,  # $0.0015 per 1K tokens for input
        "output": 0.002  # $0.002 per 1K tokens for output
    },
    # GPT-5 (via OpenRouter)
    "openai/gpt-5": {
        "input": 0.00125,  # $1.25 per 1M tokens = $0.00125 per 1K tokens for input
        "output": 0.01     # $10 per 1M tokens = $0.01 per 1K tokens for output
    },
    # Anthropic Models (via OpenRouter)
    "o3": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o3-mini": {
        "input": 0.003,  # $0.003 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    "o3-pro": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o1": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o1-pro": {
        "input": 0.015,  # $0.015 per 1K tokens for input
        "output": 0.06   # $0.06 per 1K tokens for output
    },
    "o1-mini": {
        "input": 0.003,  # $0.003 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    "o4-mini": {
        "input": 0.003,  # $0.003 per 1K tokens for input
        "output": 0.015  # $0.015 per 1K tokens for output
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-coder": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-coder-33b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-coder-6.7b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-llm-67b-chat": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-llm-7b-chat": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-math-7b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-reasoner-7b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-reasoner-34b-instruct": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    "deepseek/deepseek-r1": {
        "input": 0.00014,  # $0.00014 per 1K tokens for input
        "output": 0.00028  # $0.00028 per 1K tokens for output
    },
    # Google Models (via OpenRouter)
    "google/gemini-1.5-flash": {
        "input": 0.000075,  # $0.000075 per 1K tokens for input
        "output": 0.0003    # $0.0003 per 1K tokens for output
    },
    "google/gemini-1.5-pro": {
        "input": 0.00375,   # $0.00375 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    "google/gemini-2.0-flash-exp": {
        "input": 0.000075,  # $0.000075 per 1K tokens for input
        "output": 0.0003    # $0.0003 per 1K tokens for output
    },
    "google/gemini-2.0-pro-exp": {
        "input": 0.00375,   # $0.00375 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-4-maverick": {
        "input": 0.00015,   # $0.15 per 1M tokens = $0.00015 per 1K tokens
        "output": 0.0006    # $0.60 per 1M tokens = $0.0006 per 1K tokens
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "input": 0.00013,   # $0.13 per 1M tokens = $0.00013 per 1K tokens
        "output": 0.0006    # $0.60 per 1M tokens = $0.0006 per 1K tokens
    },
    # Mistral Models (via OpenRouter)
    "mistralai/mistral-small-3.2-24b-instruct:free": {
        "input": 0.0,       # Free tier - no cost for input
        "output": 0.0       # Free tier - no cost for output
    },
    # Meta Llama Guard Models (via OpenRouter)
    "meta-llama/llama-guard-4-12b": {
        "input": 0.0001,    # $0.0001 per 1K tokens for input
        "output": 0.0002    # $0.0002 per 1K tokens for output
    },
    # Anthropic Claude Models (via OpenRouter)
    "anthropic/claude-sonnet-4": {
        "input": 0.003,     # $0.003 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    "anthropic/claude-opus-4": {
        "input": 0.015,     # $0.015 per 1K tokens for input
        "output": 0.075     # $0.075 per 1K tokens for output
    },
    # Meta Llama Scout Models (via OpenRouter)
    "meta-llama/llama-4-scout:free": {
        "input": 0.0,       # Free tier - no cost for input
        "output": 0.0       # Free tier - no cost for output
    },
    # Google Gemini Models (via OpenRouter)
    "google/gemini-2.5-pro": {
        "input": 0.00375,   # $0.00375 per 1K tokens for input
        "output": 0.015     # $0.015 per 1K tokens for output
    },
    "google/gemini-2.0-flash-001": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens
        "output": 0.0004    # $0.40 per 1M tokens = $0.0004 per 1K tokens
    },
    "google/gemini-2.5-flash": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens
        "output": 0.0004    # $0.40 per 1M tokens = $0.0004 per 1K tokens
    },
    # X.AI Models (via OpenRouter)
    "x-ai/grok-4": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens for input
        "output": 0.0004    # $0.40 per 1M tokens = $0.0004 per 1K tokens for output
    },
    # Mistral Models (via OpenRouter)
    "mistralai/codestral-2508": {
        "input": 0.0003,    # $0.30 per 1M tokens = $0.0003 per 1K tokens for input
        "output": 0.0009    # $0.90 per 1M tokens = $0.0009 per 1K tokens for output
    },
    "mistralai/mixtral-8x22b-instruct": {
        "input": 0.0009,    # $0.90 per 1M tokens = $0.0009 per 1K tokens for input
        "output": 0.0009    # $0.90 per 1M tokens = $0.0009 per 1K tokens for output
    },
    "mistralai/mixtral-8x7b-instruct": {
        "input": 0.0009,    # $0.90 per 1M tokens = $0.0009 per 1K tokens for input
        "output": 0.0009    # $0.90 per 1M tokens = $0.0009 per 1K tokens for output
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "input": 0.00013,   # $0.13 per 1M tokens = $0.00013 per 1K tokens for input
        "output": 0.0006    # $0.60 per 1M tokens = $0.0006 per 1K tokens for output
    },
    "qwen/qwen3-coder": {
        "input": 0.0002,    # $0.20 per 1M tokens = $0.0002 per 1K tokens for input
        "output": 0.0008    # $0.80 per 1M tokens = $0.0008 per 1K tokens for output
    },
    "qwen/qwen-2.5-coder-32b-instruct": {
        "input": 0.00005,   # $0.05 per 1M tokens = $0.00005 per 1K tokens for input
        "output": 0.0002    # $0.20 per 1M tokens = $0.0002 per 1K tokens for output
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-3.1-70b-instruct": {
        "input": 0.0001,    # $0.10 per 1M tokens = $0.0001 per 1K tokens for input
        "output": 0.00028   # $0.28 per 1M tokens = $0.00028 per 1K tokens for output
    },
    "meta-llama/llama-4-scout": {
        "input": 0.0001,    # Assumed pricing per 1K tokens for input
        "output": 0.00028   # Assumed pricing per 1K tokens for output
    },
    # OpenAI OSS Models (via OpenRouter)
    "openai/gpt-oss-120b": {
        "input": 0.0005,    # Assumed pricing per 1K tokens for input
        "output": 0.0015    # Assumed pricing per 1K tokens for output
    },
    "openai/gpt-oss-20b": {
        "input": 0.0002,    # Assumed pricing per 1K tokens for input
        "output": 0.0006    # Assumed pricing per 1K tokens for output
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-r1-distill-llama-70b": {
        "input": 0.000026,  # $0.026 per 1M tokens = $0.000026 per 1K tokens for input
        "output": 0.000104  # $0.104 per 1M tokens = $0.000104 per 1K tokens for output
    },
    "deepseek/deepseek-chat-v3.1": {
        "input": 0.00014,   # $0.14 per 1M tokens = $0.00014 per 1K tokens for input
        "output": 0.00028   # $0.28 per 1M tokens = $0.00028 per 1K tokens for output
    },
    # BigCode Models (via OpenRouter)
    "bigcode/starcoder2-15b-instruct": {
        "input": 0.00014,   # $0.14 per 1M tokens = $0.00014 per 1K tokens for input
        "output": 0.00028   # $0.28 per 1M tokens = $0.00028 per 1K tokens for output
    }
}

# Model-specific configurations
MODEL_CONFIGS = {
    # OpenAI Models
    "gpt-5": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-5 model with full parameter support",
        "provider": "openai"
    },
    "gpt-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-4 model with full parameter support",
        "provider": "openai"
    },
    "gpt-4-turbo": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-4 Turbo model with full parameter support",
        "provider": "openai"
    },
    "gpt-4o": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4o",
        "description": "GPT-4o model with full parameter support",
        "provider": "openai"
    },
    "gpt-4-turbo-preview": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-4 Turbo Preview model with full parameter support",
        "provider": "openai"
    },
    "gpt-3.5-turbo": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-3.5-turbo",
        "description": "GPT-3.5 Turbo model with full parameter support",
        "provider": "openai"
    },
    "gpt-3.5-turbo-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-3.5-turbo",
        "description": "GPT-3.5 Turbo Instruct model with full parameter support",
        "provider": "openai"
    },
    # GPT-5 (via OpenRouter)
    "openai/gpt-5": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "GPT-5 model with full parameter support via OpenRouter",
        "provider": "openrouter"
    },
    # Anthropic Models (via OpenRouter)
    "o3": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o3 model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o3-mini": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o3-mini model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o3-pro": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty", "reasoning"],
        "tokenizer": "gpt-4",
        "description": "o3-pro model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature, uses OpenAI response API",
        "provider": "openai"
    },
    "o1": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o1 model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o1-pro": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o1-pro model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o1-mini": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o1-mini model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    "o4-mini": {
        "max_temperature": 1.0,
        "default_temperature": 0.0,
        "supported_parameters": ["max_completion_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "o4-mini model with temperature range 0-1, uses max_completion_tokens, does NOT support temperature",
        "provider": "openrouter"
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-coder": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Coder model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-coder-33b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Coder 33B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-coder-6.7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Coder 6.7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-llm-67b-chat": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek LLM 67B Chat model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-llm-7b-chat": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek LLM 7B Chat model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-math-7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Math 7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-reasoner-7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Reasoner 7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-reasoner-34b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Reasoner 34B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-r1": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek R1 model with full parameter support",
        "provider": "openrouter"
    },
    # Google Models (via OpenRouter)
    "google/gemini-1.5-flash": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 1.5 Flash model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-1.5-pro": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 1.5 Pro model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.0-flash-exp": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.0 Flash Experimental model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.0-pro-exp": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.0 Pro Experimental model with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-4-maverick": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama 4 Maverick model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen 3.3B model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Mistral Models (via OpenRouter)
    "mistralai/mistral-small-3.2-24b-instruct:free": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Small 3.2B Instruct model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Guard Models (via OpenRouter)
    "meta-llama/llama-guard-4-12b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama Guard 4 12B model with full parameter support",
        "provider": "openrouter"
    },
    # Anthropic Claude Models (via OpenRouter)
    "anthropic/claude-sonnet-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Anthropic Claude Sonnet 4 model with full parameter support",
        "provider": "openrouter"
    },
    "anthropic/claude-opus-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Anthropic Claude Opus 4 model with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Scout Models (via OpenRouter)
    "meta-llama/llama-4-scout:free": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama Scout 4 model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # Google Gemini Models (via OpenRouter)
    "google/gemini-2.5-pro": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.5 Pro model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.0-flash-001": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.0 Flash model with full parameter support",
        "provider": "openrouter"
    },
    "google/gemini-2.5-flash": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Google Gemini 2.5 Flash model with full parameter support",
        "provider": "openrouter"
    },
    # X.AI Models (via OpenRouter)
    "x-ai/grok-4": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "X.AI Grok-4 model with full parameter support",
        "provider": "openrouter"
    },
    # Mistral Models (via OpenRouter)
    "mistralai/codestral-2508": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Codestral 2508 model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    "mistralai/mixtral-8x22b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Mixtral 8x22B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "mistralai/mixtral-8x7b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Mistral Mixtral 8x7B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    # Qwen Models (via OpenRouter)
    "qwen/qwen3-235b-a22b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen3 235B A22B MoE model with full parameter support",
        "provider": "openrouter"
    },
    "qwen/qwen3-coder": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen3 Coder 480B MoE model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    "qwen/qwen-2.5-coder-32b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Qwen2.5 Coder 32B Instruct model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    # Meta Llama Models (via OpenRouter)
    "meta-llama/llama-3.1-70b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama 3.1 70B Instruct model with full parameter support",
        "provider": "openrouter"
    },
    "meta-llama/llama-4-scout": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "Meta Llama Scout 4 model (free tier) with full parameter support",
        "provider": "openrouter"
    },
    # DeepSeek Models (via OpenRouter)
    "deepseek/deepseek-r1-distill-llama-70b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek R1 Distill Llama 70B model with full parameter support",
        "provider": "openrouter"
    },
    "deepseek/deepseek-chat-v3.1": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "DeepSeek Chat v3.1 model with full parameter support",
        "provider": "openrouter"
    },
    # BigCode Models (via OpenRouter)
    "bigcode/starcoder2-15b-instruct": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "BigCode StarCoder2 15B Instruct model specialized for coding tasks with full parameter support",
        "provider": "openrouter"
    },
    "openai/gpt-oss-120b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "OpenAI GPT-OSS 120B model with full parameter support",
        "provider": "openrouter"
    },
    "openai/gpt-oss-20b": {
        "max_temperature": 2.0,
        "default_temperature": 0.0,
        "supported_parameters": ["temperature", "max_tokens", "top_p", "frequency_penalty", "presence_penalty"],
        "tokenizer": "gpt-4",
        "description": "OpenAI GPT-OSS 20B model with full parameter support",
        "provider": "openrouter"
    }
}

def is_openai_model(model: str) -> bool:
    """
    Check if a model is an OpenAI model.
    
    Args:
        model (str): Model name
        
    Returns:
        bool: True if it's an OpenAI model, False otherwise
    """
    # Special case: o3-pro uses OpenAI API but has special handling
    if model == "o3-pro":
        return True
    
    config = get_model_config(model)
    return config.get("provider", "openai") == "openai"

def get_model_config(model: str) -> dict:
    """
    Get configuration for a specific model.
    
    Args:
        model (str): Model name
        
    Returns:
        dict: Model configuration
        
    Raises:
        ValueError: If model is not supported
    """
    if model not in MODEL_CONFIGS:
        raise ValueError(f"Model '{model}' is not supported. Supported models: {list(MODEL_CONFIGS.keys())}")
    
    return MODEL_CONFIGS[model]

def validate_model_parameters(model: str, **kwargs) -> dict:
    """
    Validate and normalize parameters for a specific model.
    
    Args:
        model (str): Model name
        **kwargs: Parameters to validate
        
    Returns:
        dict: Validated and normalized parameters
        
    Raises:
        ValueError: If parameters are invalid for the model
    """
    config = get_model_config(model)
    validated_params = {}
    
    # Only add temperature if supported
    if 'temperature' in config['supported_parameters']:
        if 'temperature' in kwargs:
            temp = kwargs['temperature']
            max_temp = config['max_temperature']
            if not (0 <= temp <= max_temp):
                raise ValueError(f"Temperature must be between 0 and {max_temp} for model {model}. Got: {temp}")
            validated_params['temperature'] = temp
        else:
            validated_params['temperature'] = config['default_temperature']
    
    # Map max_tokens to max_completion_tokens for models that require it
    if 'max_tokens' in kwargs and 'max_completion_tokens' in config['supported_parameters']:
        validated_params['max_completion_tokens'] = kwargs['max_tokens']
    elif 'max_tokens' in kwargs:
        validated_params['max_tokens'] = kwargs['max_tokens']
    
    # Validate other parameters
    supported_params = config['supported_parameters']
    for param, value in kwargs.items():
        if param == 'max_tokens' and 'max_completion_tokens' in supported_params:
            continue  # already mapped
        if param in supported_params:
            validated_params[param] = value
        else:
            print(f"Warning: Parameter '{param}' is not supported for model {model}. Supported: {supported_params}")
    
    return validated_params

def count_tokens(text: str, model: str) -> int:
    """Count the number of tokens in a text string."""
    try:
        config = get_model_config(model)
        tokenizer_name = config['tokenizer']
        encoding = tiktoken.encoding_for_model(tokenizer_name)
        return len(encoding.encode(text))
    except Exception as e:
        print(f"Warning: Could not get tokenizer for model {model}, using GPT-4 tokenizer as fallback: {e}")
        try:
            # Fallback to GPT-4 tokenizer
            encoding = tiktoken.encoding_for_model("gpt-4")
            return len(encoding.encode(text))
        except Exception as fallback_error:
            print(f"Error: Could not use GPT-4 tokenizer as fallback: {fallback_error}")
            # Final fallback: rough estimation (1 token ≈ 4 characters for English text)
            estimated_tokens = len(text) // 4
            print(f"Using rough estimation: {estimated_tokens} tokens (based on character count)")
            return estimated_tokens

def calculate_cost(input_tokens: int, output_tokens: int, model: str) -> float:
    """Calculate the cost of an API call based on token counts."""
    if model not in MODEL_PRICING:
        print(f"Warning: No pricing information available for model {model}. Using GPT-4 pricing as fallback.")
        model = "gpt-4"  # Fallback to GPT-4 pricing
    
    input_cost = (input_tokens / 1000) * MODEL_PRICING[model]["input"]
    output_cost = (output_tokens / 1000) * MODEL_PRICING[model]["output"]
    return input_cost + output_cost

def send_to_llm(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to LLM API (OpenAI or OpenRouter) and return the response.
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    # Special handling for o3-pro model (uses response API instead of chat completion)
    if model == "o3-pro":
        return send_to_o3_pro(prompt, model, temperature, enable_token_counting, **kwargs)
    
    # Route to appropriate provider based on model
    if is_openai_model(model):
        return send_to_openai(prompt, model, temperature, enable_token_counting, **kwargs)
    else:
        return send_to_openrouter(prompt, model, temperature, enable_token_counting, **kwargs)

def send_to_openai(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to OpenAI API and return the response.
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    try:
        # Create OpenAI client with timeout settings
        client = OpenAI(
            timeout=30.0,  # 30 second timeout
            max_retries=2
        )
    except Exception as e:
        print(f"Error creating OpenAI client: {e}")
        print("This might be due to network/SSL issues. Please check your internet connection.")
        raise
    
    # Validate and normalize parameters for the specific model
    try:
        params = {'temperature': temperature} if temperature is not None else {}
        params.update(kwargs)
        validated_params = validate_model_parameters(model, **params)
    except ValueError as e:
        print(f"Parameter validation error: {e}")
        raise
    
    # Initialize token counts
    input_tokens = None
    output_tokens = None
    cost = None
    
    # Count input tokens if enabled
    if enable_token_counting:
        try:
            input_tokens = count_tokens(prompt, model)
        except Exception as e:
            print(f"Warning: Could not count input tokens: {e}")
            input_tokens = None
    
    # Prepare API call parameters
    api_params = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a security assistant."},
            {"role": "user", "content": prompt}
        ],
        **validated_params
    }
    
    # Make the API call
    try:
        response = client.chat.completions.create(**api_params)
    except Exception as e:
        print(f"Error making API call: {e}")
        print("This might be due to network issues, API key problems, or rate limiting.")
        raise
    
    # Count output tokens if enabled
    if enable_token_counting:
        try:
            output_tokens = count_tokens(response.choices[0].message.content, model)
        except Exception as e:
            print(f"Warning: Could not count output tokens: {e}")
            output_tokens = None
    
    # Calculate cost if we have token counts
    if input_tokens is not None and output_tokens is not None:
        try:
            cost = calculate_cost(input_tokens, output_tokens, model)
        except Exception as e:
            print(f"Warning: Could not calculate cost: {e}")
            cost = None
    
    # Print token usage and cost information in a formatted way
    print("\n" + "="*50)
    print(f"OpenAI API Call Summary (Model: {model})")
    print("-"*50)
    if input_tokens is not None:
        print(f"Input tokens:  {input_tokens:>8}")
    else:
        print(f"Input tokens:  {'N/A':>8} (counting disabled/failed)")
    
    if output_tokens is not None:
        print(f"Output tokens: {output_tokens:>8}")
    else:
        print(f"Output tokens: {'N/A':>8} (counting disabled/failed)")
    
    if input_tokens is not None and output_tokens is not None:
        print(f"Total tokens:  {input_tokens + output_tokens:>8}")
    else:
        print(f"Total tokens:  {'N/A':>8} (counting disabled/failed)")
    
    print("-"*50)
    if cost is not None:
        print(f"Estimated cost: ${cost:.4f}")
    else:
        print(f"Estimated cost: N/A (counting disabled/failed)")
    
    # Print model-specific information
    config = get_model_config(model)
    print(f"Model config: {config['description']}")
    print(f"Parameters used: {validated_params}")
    print("="*50 + "\n")
    
    return response.choices[0].message.content

def send_to_openrouter(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to OpenRouter API and return the response.
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    try:
        # Create OpenRouter client with timeout settings
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv('OPENROUTER_API_KEY'),
            timeout=30.0,  # 30 second timeout
            max_retries=2
        )
    except Exception as e:
        print(f"Error creating OpenRouter client: {e}")
        print("This might be due to network/SSL issues. Please check your internet connection.")
        raise
    
    # Validate and normalize parameters for the specific model
    try:
        params = {'temperature': temperature} if temperature is not None else {}
        params.update(kwargs)
        validated_params = validate_model_parameters(model, **params)
    except ValueError as e:
        print(f"Parameter validation error: {e}")
        raise
    
    # Initialize token counts
    input_tokens = None
    output_tokens = None
    cost = None
    
    # Count input tokens if enabled
    if enable_token_counting:
        try:
            input_tokens = count_tokens(prompt, model)
        except Exception as e:
            print(f"Warning: Could not count input tokens: {e}")
            input_tokens = None
    
    # Prepare API call parameters
    api_params = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a security assistant."},
            {"role": "user", "content": prompt}
        ],
        **validated_params
    }
    
    # Make the API call
    try:
        response = client.chat.completions.create(**api_params)
    except Exception as e:
        print(f"Error making OpenRouter API call: {e}")
        print("This might be due to network issues, API key problems, or rate limiting.")
        raise
    
    # Count output tokens if enabled
    if enable_token_counting:
        try:
            output_tokens = count_tokens(response.choices[0].message.content, model)
        except Exception as e:
            print(f"Warning: Could not count output tokens: {e}")
            output_tokens = None
    
    # Calculate cost if we have token counts
    if input_tokens is not None and output_tokens is not None:
        try:
            cost = calculate_cost(input_tokens, output_tokens, model)
        except Exception as e:
            print(f"Warning: Could not calculate cost: {e}")
            cost = None
    
    # Print token usage and cost information in a formatted way
    print("\n" + "="*50)
    print(f"OpenRouter API Call Summary (Model: {model})")
    print("-"*50)
    if input_tokens is not None:
        print(f"Input tokens:  {input_tokens:>8}")
    else:
        print(f"Input tokens:  {'N/A':>8} (counting disabled/failed)")
    
    if output_tokens is not None:
        print(f"Output tokens: {output_tokens:>8}")
    else:
        print(f"Output tokens: {'N/A':>8} (counting disabled/failed)")
    
    if input_tokens is not None and output_tokens is not None:
        print(f"Total tokens:  {input_tokens + output_tokens:>8}")
    else:
        print(f"Total tokens:  {'N/A':>8} (counting disabled/failed)")
    
    print("-"*50)
    if cost is not None:
        print(f"Estimated cost: ${cost:.4f}")
    else:
        print(f"Estimated cost: N/A (counting disabled/failed)")
    
    # Print model-specific information
    config = get_model_config(model)
    print(f"Model config: {config['description']}")
    print(f"Parameters used: {validated_params}")
    print("="*50 + "\n")
    
    return response.choices[0].message.content

def send_to_o3_pro(prompt, model, temperature=None, enable_token_counting=True, **kwargs):
    """
    Send a prompt to o3-pro model using OpenAI's response API (not chat completion).
    
    Args:
        prompt (str): The prompt to send
        model (str): The model to use (should be "o3-pro")
        temperature (float, optional): Temperature for response generation
        enable_token_counting (bool): Whether to count tokens and calculate cost
        **kwargs: Additional model-specific parameters (max_tokens, top_p, etc.)
    
    Returns:
        str: The response from the model
    """
    try:
        # Create OpenAI client with timeout settings
        client = OpenAI(
            timeout=60.0,  # Longer timeout for o3-pro as it may take more time
            max_retries=2
        )
    except Exception as e:
        print(f"Error creating OpenAI client: {e}")
        print("This might be due to network/SSL issues. Please check your internet connection.")
        raise
    
    # Validate and normalize parameters for the specific model
    try:
        params = {'temperature': temperature} if temperature is not None else {}
        params.update(kwargs)
        validated_params = validate_model_parameters(model, **params)
    except ValueError as e:
        print(f"Parameter validation error: {e}")
        raise
    
    # Initialize token counts
    input_tokens = None
    output_tokens = None
    cost = None
    
    # Count input tokens if enabled
    if enable_token_counting:
        try:
            input_tokens = count_tokens(prompt, model)
        except Exception as e:
            print(f"Warning: Could not count input tokens: {e}")
            input_tokens = None
    
    # Prepare API call parameters for o3-pro response API
    api_params = {
        "model": model,
        "input": [
            {"role": "system", "content": "You are a security assistant specialized in vulnerability analysis."},
            {"role": "user", "content": prompt}
        ],
        "reasoning": {"effort": "high"},  # Enable high reasoning for best performance
        **validated_params
    }
    
    # Make the API call using responses API (no chat completion fallback)
    try:
        response = client.responses.create(**api_params)
    except Exception as e:
        print(f"Error making o3-pro API call: {e}")
        print("This might be due to network issues, API key problems, or rate limiting.")
        raise
    
    # Count output tokens if enabled
    if enable_token_counting:
        try:
            output_tokens = count_tokens(response.output_text, model)
        except Exception as e:
            print(f"Warning: Could not count output tokens: {e}")
            output_tokens = None
    
    # Calculate cost if we have token counts
    if input_tokens is not None and output_tokens is not None:
        try:
            cost = calculate_cost(input_tokens, output_tokens, model)
        except Exception as e:
            print(f"Warning: Could not calculate cost: {e}")
            cost = None
    
    # Print token usage and cost information in a formatted way
    print("\n" + "="*50)
    print(f"o3-pro Response API Call Summary (Model: {model})")
    print("-"*50)
    if input_tokens is not None:
        print(f"Input tokens:  {input_tokens:>8}")
    else:
        print(f"Input tokens:  {'N/A':>8} (counting disabled/failed)")
    
    if output_tokens is not None:
        print(f"Output tokens: {output_tokens:>8}")
    else:
        print(f"Output tokens: {'N/A':>8} (counting disabled/failed)")
    
    if input_tokens is not None and output_tokens is not None:
        print(f"Total tokens:  {input_tokens + output_tokens:>8}")
    else:
        print(f"Total tokens:  {'N/A':>8} (counting disabled/failed)")
    
    print("-"*50)
    if cost is not None:
        print(f"Estimated cost: ${cost:.4f}")
    else:
        print(f"Estimated cost: N/A (counting disabled/failed)")
    
    # Print model-specific information
    config = get_model_config(model)
    print(f"Model config: {config['description']}")
    print(f"Parameters used: {validated_params}")
    print(f"Reasoning effort: High")
    print("="*50 + "\n")
    
    return response.output_text

def list_supported_models():
    """
    List all supported models with their configurations.
    
    Returns:
        dict: Dictionary of model configurations
    """
    return MODEL_CONFIGS

def get_model_info(model: str) -> dict:
    """
    Get detailed information about a specific model.
    
    Args:
        model (str): Model name
        
    Returns:
        dict: Model information including pricing and configuration
    """
    if model not in MODEL_CONFIGS:
        raise ValueError(f"Model '{model}' is not supported")
    
    config = MODEL_CONFIGS[model]
    pricing = MODEL_PRICING.get(model, {})
    
    return {
        "model": model,
        "config": config,
        "pricing": pricing,
        "supported_parameters": config["supported_parameters"],
        "max_temperature": config["max_temperature"],
        "default_temperature": config["default_temperature"],
        "provider": config["provider"]
    }

def test_model_connectivity(model_name="gpt-4o"):
    """
    Test if a model is accessible with the current API key.
    
    Args:
        model_name (str): The model to test
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if is_openai_model(model_name):
            client = OpenAI(timeout=10.0)
            print("✓ OpenAI client created successfully")
        else:
            client = OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=os.getenv('OPENROUTER_API_KEY'),
                timeout=10.0
            )
            print("✓ OpenRouter client created successfully")
        return True
    except Exception as e:
        print(f"✗ Error creating client: {e}")
        print("Please check your internet connection and API key configuration.")
        return False

def test_openrouter_connectivity():
    """
    Test OpenRouter connectivity specifically.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv('OPENROUTER_API_KEY'),
            timeout=10.0
        )
        print("✓ OpenRouter client created successfully")
        return True
    except Exception as e:
        print(f"✗ Error creating OpenRouter client: {e}")
        print("Please check your internet connection and OpenRouter API key configuration.")
        return False

def validate_api_key():
    """
    Validate that the required API key is set.
    
    Returns:
        bool: True if API key is set, False otherwise
    """
    # Check for OpenAI API key
    if not os.getenv('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY environment variable is not set.")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        return False
    
    # Check for OpenRouter API key (required for non-OpenAI models)
    if not os.getenv('OPENROUTER_API_KEY'):
        print("Warning: OPENROUTER_API_KEY environment variable is not set.")
        print("This is required for non-OpenAI models (DeepSeek, Google Gemini, etc.).")
        print("Please set your OpenRouter API key:")
        print("export OPENROUTER_API_KEY='your-openrouter-api-key-here'")
        print("You can get one from: https://openrouter.ai/")
        return False
    
    return True

def validate_openai_api_key():
    """
    Validate that the OpenAI API key is set.
    
    Returns:
        bool: True if API key is set, False otherwise
    """
    if not os.getenv('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY environment variable is not set.")
        print("Please set your OpenAI API key:")
        print("export OPENAI_API_KEY='your-api-key-here'")
        return False
    return True

def validate_openrouter_api_key():
    """
    Validate that the OpenRouter API key is set.
    
    Returns:
        bool: True if API key is set, False otherwise
    """
    if not os.getenv('OPENROUTER_API_KEY'):
        print("Error: OPENROUTER_API_KEY environment variable is not set.")
        print("Please set your OpenRouter API key:")
        print("export OPENROUTER_API_KEY='your-openrouter-api-key-here'")
        print("You can get one from: https://openrouter.ai/")
        return False
    return True 
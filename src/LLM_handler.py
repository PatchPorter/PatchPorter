import os
import json
import ollama
from openai import OpenAI

class LLMHandler:
    def __init__(self, project):
        self.project = project
        self.prj_path = project.prj_path
        self.challenge_version = self.project.get_challenge_version()
        self.prompt_path = os.path.join(self.prj_path, 'prompt')

        line_prompt_file = os.path.join(self.prompt_path, f'{self.challenge_version}-line_fault_localization.json')
        context_prompt_file = os.path.join(self.prompt_path, f'{self.challenge_version}-fault_localization.json')
        file_prompt_file = os.path.join(self.prompt_path, f'{self.challenge_version}.json')
        self.prompt_file_paths = [context_prompt_file, file_prompt_file, line_prompt_file]
        # self.prompt_file_paths = [line_prompt_file]
        self.model_list = ['deepseek-api']

    def model_infer(self, model):
        prompt_file_paths = [os.path.join(self.prompt_path, i) for i in os.listdir(self.prompt_path)]
        for prompt_file_path in prompt_file_paths:
            if model != prompt_file_path.split('@')[1]:
            # if model not in prompt_file_path:
                continue
            output = []
            try:
                with open(prompt_file_path, 'r') as f:
                    json_content = json.load(f)
            except:
                with open('./log/missing_file.txt', 'a') as f:
                    print(prompt_file_path, file=f)
                    continue
            # if f"{model}-output" in json_content:
            #     continue
            print(prompt_file_path)
            cost = 0
            for prompt in json_content['prompt']:
                # if 'gemini' in model: output.append(gemini(prompt['prompt']))
                # elif 'gpt4o' in model: output.append(gpt4o(prompt['prompt']))
                # elif 'deepseek-api' not in model:
                #     output.append(ask_ollama(model, prompt['prompt']))
                # else: output.append(deepseek_api(prompt['prompt']))
                output.append(deepseek_api(prompt['prompt'])[0])
                cost += deepseek_api(prompt['prompt'])[-1]
            json_content[f'{model}-output'] = output
            with open(f'./cost/test.txt', 'a') as f:
                print(cost, file=f)
            # with open(prompt_file_path, 'w') as f:
            #     json.dump(json_content, f, indent=4)

    def infer(self):
        for model in self.model_list:
            for prompt_file_path in self.prompt_file_paths:
                output = []
                try:
                    with open(prompt_file_path, 'r') as f:
                        json_content = json.load(f)
                except:
                    with open('./missing_file.txt', 'a') as f:
                        print(prompt_file_path, file=f)
                        continue
                # if f"{model}-output" in json_content:
                #     continue
                for prompt in json_content['prompt']:
                    if 'gemini' in model: output.append(gemini(prompt['prompt']))
                    elif 'gpt4o' in model: output.append(gpt4o(prompt['prompt']))
                    elif 'deepseek-api' not in model:
                        output.append(ask_ollama(model, prompt))
                    else: output.append(deepseek_api(prompt))
                json_content[f'{model}-output'] = output
                with open(prompt_file_path, 'w') as f:
                    json.dump(json_content, f, indent=4)

def LLM_infer(content, model):
    if model == 'deepseek-api':
        return deepseek_api(content)
    elif model == 'gpt4o':
        return  gpt4o(content)
    elif model == 'gemini':
        return gemini(content)
    else:
        return ask_ollama(model, content)

def ask_ollama(model, content):
    if len(content) > 25000:
        return ''
    response = ollama.generate(model=model, prompt=content, keep_alive=-1, options={'tempature': 0, 'top_p': 0.5, 'seed': 14, 'top_k': 1})
    return response['response']

def deepseek_api(content):
    key = ""
    api = ""
    model = "deepseek-chat"
    # model = "deepseek-reasoner"
    client = OpenAI(api_key=key, base_url=api)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "user", "content": content},
        ],
        stream=False,
        temperature=0
    )
    return response.choices[0].message.content, response.usage.total_tokens

def gpt4o(content):
    client = OpenAI(api_key="", base_url="")
    response = client.chat.completions.create(
        model="gpt-4o",
        stream=False,
        messages=[
            {"role": "user", "content": content},
        ],
        temperature=0
    )
    usage = response.usage
    with open(f'./cost/gpt4o.txt', 'a') as f:
        print(usage.total_tokens, file=f)
    return response.choices[0].message.content

# def gemini(content):
#     client = OpenAI(api_key="", base_url="")
#     response = client.chat.completions.create(
#         model="gemini-2.5-flash",
#         stream=False,
#         messages=[
#             {"role": "user", "content": content},
#         ],
#         temperature=0
#     )
#     usage = response.usage
#     with open(f'./cost/gemini.txt', 'a') as f:
#         print(usage.total_tokens, file=f)
#     return response.choices[0].message.content


def gemini(content, retries=10):
    import openai
    import time
    client = OpenAI(
        api_key="",
        base_url=""
    )
    attempt = 0
    while attempt < retries:
        try:
            response = client.chat.completions.create(
                model="gemini-2.5-flash",
                stream=False,
                messages=[
                    {"role": "user", "content": content},
                ],
                temperature=0
            )
            return response.choices[0].message.content

        except openai.InternalServerError as e:
            attempt += 1
            time.sleep(2 ** attempt)

        except Exception as e:
            raise e
    raise APIRequestFailedError(f"API。")

class APIRequestFailedError(Exception):
    pass

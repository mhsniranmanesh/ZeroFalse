import argparse


class Arguments:
    def __init__(self, tmp_args):
        # SARIF analyzer arguments
        self.__sarif_file = tmp_args.sarif_file
        self.__project_src_root = tmp_args.project_src_root
        self.__template_path = tmp_args.template_path
        self.__model = tmp_args.model
        self.__temperature = tmp_args.temperature
        self.__expected_results_csv = tmp_args.expected_results_csv
        self.__run_id = tmp_args.run_id
        self.__enable_token_counting = tmp_args.enable_token_counting
        self.__prompt_version = tmp_args.prompt_version
        self.__dataset = tmp_args.dataset
        self.__batch_size = tmp_args.batch_size
        self.__max_workers = tmp_args.max_workers

    # SARIF analyzer properties
    @property
    def sarif_file(self):
        return self.__sarif_file

    @property
    def project_src_root(self):
        return self.__project_src_root

    @property
    def template_path(self):
        return self.__template_path

    @property
    def model(self):
        return self.__model

    @property
    def temperature(self):
        return self.__temperature

    @property
    def expected_results_csv(self):
        return self.__expected_results_csv

    @property
    def run_id(self):
        return self.__run_id
    
    @property
    def enable_token_counting(self):
        return self.__enable_token_counting

    @property
    def prompt_version(self):
        return self.__prompt_version

    @property
    def dataset(self):
        return self.__dataset

    @property
    def batch_size(self):
        return self.__batch_size

    @property
    def max_workers(self):
        return self.__max_workers

    @classmethod
    def parse(cls):
        my_parser = argparse.ArgumentParser(description='SARIF Analyzer with LLM',
                                            prog='main.py',
                                            usage='%(prog)s ...')

        # SARIF analyzer arguments
        my_parser.add_argument('--sarif_file', '-sf', help='Path to the SARIF file to analyze', required=True)
        my_parser.add_argument('--project_src_root', '-psr', help='Path to the project source root', required=True)
        my_parser.add_argument('--template_path', '-tp', help='Path to the prompt template file (optional, will be auto-detected from SARIF filename)', required=False)
        my_parser.add_argument('--model', '-md', help='OpenAI model to use', default='gpt-4o')
        my_parser.add_argument('--temperature', '-t', help='Temperature for OpenAI API', default=0.0, type=float)
        my_parser.add_argument('--expected_results_csv', '-erc', help='Path to the expected results CSV file', required=True)
        my_parser.add_argument('--run_id', '-rid', help='Unique run ID for this analysis (optional, used for logging)', required=False, default='default')
        my_parser.add_argument('--enable_token_counting', '-etc', help='Enable token counting', action='store_true')
        my_parser.add_argument('--prompt_version', '-pv', help='Prompt template version (e.g., v1, v2). Default: v2', default='v2')
        my_parser.add_argument('--dataset', '-ds', help='Dataset type (owasp). Default: owasp', default='owasp')
        my_parser.add_argument('--batch_size', '-bs', help='Number of prompts to process concurrently (default: 5)', type=int, default=5)
        my_parser.add_argument('--max_workers', '-mw', help='Maximum number of concurrent API calls (default: 10)', type=int, default=10)

        tmp_args = my_parser.parse_args()

        return Arguments(tmp_args)

    def __repr__(self):
        return f'An object of class Arguments:\n' \
            f'{self.sarif_file = }\n' \
            f'{self.project_src_root = }\n' \
            f'{self.template_path = }\n' \
            f'{self.model = }\n' \
            f'{self.temperature = }\n' \
            f'{self.expected_results_csv = }\n' \
            f'{self.run_id = }\n' \
            f'{self.enable_token_counting = }\n' \
            f'{self.prompt_version = }\n' \
            f'{self.dataset = }\n' \
            f'{self.batch_size = }\n' \
            f'{self.max_workers = }\n'

    def __str__(self) -> str:
        return (f"SF*{self.sarif_file}_PSR*{self.project_src_root}_MD*{self.model}_RID*{self.run_id}"
            )
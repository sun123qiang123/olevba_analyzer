import os
import sys
import shutil
import logging
import hashlib
import coloredlogs
from oletools import olevba
from argparse import ArgumentParser

level_styles = {'info': {'color': 'green'},
                'warning': {'color': 'yellow'},
                'debug': {'color': 'blue', 'bold': True},
                'critical': {'color': 'red', 'bold': True}}

logging.basicConfig(level=logging.INFO)
coloredlogs.install(level='DEBUG', fmt='  %(message)s', level_styles=level_styles)


class OleVbaAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        self.separator = '\n%s\n' % ('-' * 30)

        with open(self.file_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        self.analysis_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), sha256)

        if os.path.isdir(self.analysis_path):
            shutil.rmtree(self.analysis_path, ignore_errors=True)
        os.mkdir(self.analysis_path)

        self.make_analysis()

    def make_analysis(self):
        """
        Function that make the file analysis
        :return:
        """
        logging.debug('\n\n%s' % self.separator)
        ole_parser = olevba.VBA_Parser(self.file_path)
        if not ole_parser.detect_vba_macros():
            return logging.info('No VBA Macros were found in this file')
        logging.critical('VBA Macros found')

        # Extracts the macro into analysis path
        for filename, stream_path, vba_filename, vba_code in ole_parser.extract_macros():
            logging.debug(self.separator)
            logging.info('OLE stream    : %s' % stream_path)
            logging.info('VBA filename  : %s' % vba_filename)

            tp = os.path.join(self.analysis_path, vba_filename)
            with open(tp, 'w') as f:
                f.write(vba_code)

            logging.warning('\nSaved in: "%s"\n' % tp)

        # Analyze all macros
        logging.debug(self.separator)
        logging.critical('Keywords: \n')
        for kw_type, keyword, description in ole_parser.analyze_macros():
            logging.warning('Type: %s' % kw_type)
            logging.info('Keyword: %s\nDescription: %s\n' % (keyword, description))

        logging.debug(self.separator)
        logging.critical('Analysis: \n')
        logging.warning('VBA obfuscated strings: %d' % ole_parser.nb_vbastrings)
        logging.warning('IOCs: %d' % ole_parser.nb_iocs)
        logging.warning('AutoExec keywords: %d' % ole_parser.nb_autoexec)
        logging.warning('Suspicious keywords: %d' % ole_parser.nb_suspicious)
        logging.warning('Hex obfuscated strings: %d' % ole_parser.nb_hexstrings)
        logging.warning('Base64 obfuscated strings: %d' % ole_parser.nb_base64strings)
        logging.warning('Dridex obfuscated strings: %d' % ole_parser.nb_dridexstrings)

if __name__ == '__main__':

    parser = ArgumentParser(description='OLE VBA Analyzer', epilog='Example: \n OleVbaAnalyzer.exe -f "bla.doc"')
    parser.add_argument('-f', '--file', help='File path', type=str, required=False, default=False)
    parser.add_argument('-v', '--version', help='Show version', action='store_true', required=False, default=False)
    args = parser.parse_args()
    if args.version:
        from olevba_analyzer.__version__ import __version__

        logging.info('OLE VBA Analyzer version: {}'.format(__version__))
        sys.exit()

    elif args.file:
        analyzer = OleVbaAnalyzer(args.file)
    else:
        logging.info('Please, check the Help to know how to use this code :)')

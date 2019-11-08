#include"HTTPParse.h"

void HTTPParse::parse(char* data,int len) {
	size_t pos = 0, posk = 0, posv = 0;
	string k = "", v = "",http;
	char c;

	http = string(data, len);

	//http����������GET����
	while (pos != http.size())
	{
		c = http.at(pos);
		if (c == ':')
		{

			//�������У�����Ϣͷ����δ����
			if (!cmdLine.empty() && k.empty())
			{

				//�洢��Ϣͷ����
				k = http.substr(posk, pos - posk);

				//����ð�źͿո�
				posv = pos + 2;
			}
		}

		//��β
		else if (c == '\r' || c == '\n')
		{

			//��δ��������Ϣͷ�ֶ����ƣ���������Ҳδ������
			if (k.empty() && cmdLine.empty())
			{
				//����Ӧ�������У�����֮
				cmdLine = http.substr(posk, pos - posk);
			}
			else
			{

				//�ѽ�������Ϣͷ�ֶ����ƣ���δ�����ֶ�ֵ
				if (!k.empty() && v.empty())
				{

					//�洢�ֶ�ֵ
					v = http.substr(posv, pos - posv);
				}
			}
			posk = pos + 1;
		}

		if (!k.empty() && !v.empty() && !cmdLine.empty())
		{

			//������Ϣͷ�ֶ����ƺ�ֵ
			kvs.insert(make_pair(k, v));
			k = "";
			v = "";
		}
		++pos;
	}
}

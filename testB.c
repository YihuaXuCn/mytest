int main()
{
	int ret, sum, i, j, k;
	i = 0;
	j = 1;
	sum = i+j;
	j++;
	i++;
	if (i % 2 == 1)
	{
		j++;
	}
	else
	{
		k = i;
		k++;
	}
	ret = k;
	return ret;
}
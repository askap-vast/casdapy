from casdapy.casda import query_visibilities

field_names = ["1806-25", "1739-25"]
beams = [33,24]

r = query_visibilities(fieldnames_like=field_names, beams=beams)

print(r['filename'])

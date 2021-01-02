from profiles.models import ShareFile
def view_revoke():
    fileId = '1daNw1Y4XPCZCoVa1QMzZYw0CqOAqRbLv'
    a = ShareFile.objects.get(file_id_id=fileId)
    print(a)
    return a
view_revoke()
// C++ program to demonstrate the use
// of string::npos
#include <bits/stdc++.h>
using namespace std;

// Function that using string::npos
// to find the index of the occurrence
// of any string in the given string
void fun(string s1, string s2) {
    // Find position of string s2
    int found = s1.find(s2);

    // Check if position is -1 or not
    if (found != string::npos) {
        cout << found << endl;
    }

    else
        cout << "couldnt format" << endl;
}

int main()
{
    // Given strings
    string secKey = "keys-from-server/werfgds-pubkeyfromserver.derMIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAysDvhdrnVbiW0b68XXAli3eTGWjxV9cKab4MQYM+XGSix/QHZRJH82pjc59LkgI6Wl/4pF5tFBcNzKeVWzR+JRZYaMeuzIhRgK9LShcpqmimpKvhx4Wvy8H8Omr2bO0tf/FVdT6aeq8RQVGDC2MbJWov5WdBGyJ+sgBUEpWzPB3dfop83DtQbLiELd40c4DYIyYg0hKI876Rd/Xg2g5Jzip7C8soenurbudHMH8OltIoBco5ThRy/MfU/HlYFf5pBG7MBC6v0CWQXMmeh3RP2w79MPZigXifuwAgZ3GyA9UXwJhBnf+37fCIN7Ip22/IrQDt7unA4vg4JateRlfRFyuKv7VwKKLCdhmICtIdWmw3VCKM6RJQ7LJuZka2HJOeT/61/2miMMOMjA/eEx4AA+/NctS7Q5fQq9hnoqp0+JJgMjfmPfkkQd1KLeTJq96raMB+sRqDgurha799KepEWxktyrZMSTZSKRYCH9htxyLbpevNx6BoCJ5ZXsV2fVkV5AWB9C/zyxtV2CvdNAFZAYeiMGUN0vVnaU5fzDSN8iTaZ0gNaAfSxkjOt0L10303dIdXLlL0uuCr2QcKCWaAVuvL05/6RrLDU4IJfw80vDBzIO4CW4KzCKOiv5a0lL29k8MlNJB/Tnb5DMdmYL2VbWdXVQMsAtLniuBoAEiTcCsCARE=";
    string s2 = ".der";

    //keys-from-server/werfgds-pubkeyfromserver.derMIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAysDvhdrnVbiW0b68XXAli3eTGWjxV9cKab4MQYM+XGSix/QHZRJH82pjc59LkgI6Wl/4pF5tFBcNzKeVWzR+JRZYaMeuzIhRgK9LShcpqmimpKvhx4Wvy8H8Omr2bO0tf/FVdT6aeq8RQVGDC2MbJWov5WdBGyJ+sgBUEpWzPB3dfop83DtQbLiELd40c4DYIyYg0hKI876Rd/Xg2g5Jzip7C8soenurbudHMH8OltIoBco5ThRy/MfU/HlYFf5pBG7MBC6v0CWQXMmeh3RP2w79MPZigXifuwAgZ3GyA9UXwJhBnf+37fCIN7Ip22/IrQDt7unA4vg4JateRlfRFyuKv7VwKKLCdhmICtIdWmw3VCKM6RJQ7LJuZka2HJOeT/61/2miMMOMjA/eEx4AA+/NctS7Q5fQq9hnoqp0+JJgMjfmPfkkQd1KLeTJq96raMB+sRqDgurha799KepEWxktyrZMSTZSKRYCH9htxyLbpevNx6BoCJ5ZXsV2fVkV5AWB9C/zyxtV2CvdNAFZAYeiMGUN0vVnaU5fzDSN8iTaZ0gNaAfSxkjOt0L10303dIdXLlL0uuCr2QcKCWaAVuvL05/6RrLDU4IJfw80vDBzIO4CW4KzCKOiv5a0lL29k8MlNJB/Tnb5DMdmYL2VbWdXVQMsAtLniuBoAEiTcCsCARE=
    // cout << GREEN_TEXT << "CHARS OVER 5000000000000000000" << RESET_TEXT << endl;
    static string s2find = ".der";
    int found = secKey.find(".der") + s2find.length();
    if (found != string::npos) {
        string path = secKey.substr(0, found);
        cout << "new path: " << path << endl;
        string encodedKey = secKey.substr(found);
        cout << encodedKey << endl;
    }

    return 0;
}


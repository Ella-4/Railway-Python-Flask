# PPT 검색 웹앱

PowerPoint 파일을 업로드하고 제목으로 검색할 수 있는 웹 애플리케이션입니다.

## 기능
- PPT/PPTX 파일 제목 자동 추출
- 키워드 검색
- 파일 다운로드
- 관리자 도구 (파일 재스캔)

## 사용법
1. `ppt_files/` 폴더에 PPT 파일들을 업로드
2. 웹사이트에서 "파일 다시 스캔" 버튼 클릭
3. 검색 및 다운로드 사용

## Railway 배포
1. 이 저장소를 GitHub에 푸시
2. Railway에서 GitHub 저장소 연결
3. 자동 배포 완료

## 로컬 실행
```bash
pip install -r requirements.txt
python app.py
```